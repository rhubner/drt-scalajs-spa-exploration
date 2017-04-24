package passengersplits.polling

import java.util.Date

import akka.NotUsed
import akka.stream.ActorMaterializer
import akka.stream.scaladsl.Source
import com.mfglabs.stream.SinkExt
import passengersplits.core.ZipUtils

import scala.concurrent.ExecutionContext.Implicits.global
import scala.language.postfixOps
import akka.Done
import akka.actor.{Actor, ActorLogging, ActorRef, ActorSystem, Props}
import akka.event.LoggingAdapter
import akka.stream.Materializer
import akka.stream.scaladsl.{Flow, Sink}
import drt.shared.{MilliDate, SDateLike}
import org.joda.time.DateTime
import org.slf4j.{Logger, LoggerFactory}
import passengersplits.core.PassengerInfoRouterActor.{FlightPaxSplitBatchComplete, FlightPaxSplitBatchInit, PassengerSplitsAck}
import passengersplits.core.ZipUtils.UnzippedFileContent
import passengersplits.s3._
import services.SDate

import scala.collection.immutable.Seq
import scala.concurrent.duration._
import scala.concurrent.{Future, Promise}
import scala.util.{Failure, Success, Try}

object FilePolling {
  def beginPolling(log: LoggingAdapter, flightPassengerReporter: ActorRef, zipFilePath: String,
                   initialFileFilter: Option[String], portCode: String)(implicit actorSystem: ActorSystem, mat: Materializer): Future[Done] = {
    val statefulPoller: StatefulLocalFileSystemPoller = StatefulLocalFileSystemPoller(initialFileFilter, zipFilePath)
    val unzippedFileProvider: SimpleLocalFileSystemReader = statefulPoller.unzippedFileProvider
    val onNewFileSeen = statefulPoller.onNewFileSeen

    val promiseBatchDone = PromiseSignals.promisedDone
    val batchPollProcessingDone = promiseBatchDone.future

    class BatchCompletionMonitor(promise: Promise[Done]) extends Actor with ActorLogging {
      def receive: Receive = {
        case FlightPaxSplitBatchComplete(_) =>
          log.info(s"$self FlightPaxSplitBatchComplete")
          promise.complete(Try(Done))
      }
    }
    val props = Props(classOf[BatchCompletionMonitor], promiseBatchDone)
    val completionMonitor = actorSystem.actorOf(props)


    val completionMessage = FlightPaxSplitBatchComplete(completionMonitor)

    val subscriberFlightActor = Sink.actorRefWithAck(flightPassengerReporter, FlightPaxSplitBatchInit, PassengerSplitsAck, completionMessage)

    val unzipFlow = Flow[String]
      .mapAsync(1)(unzippedFileProvider.zipFilenameToEventualFileContent(_))
      .mapConcat(unzippedFileContents => unzippedFileContents.map(uzfc => VoyagePassengerInfoParser.parseVoyagePassengerInfo(uzfc.content)))
      .collect {
        case Success(vpi) if vpi.ArrivalPortCode == portCode => vpi
      }.map(uzfc => {
      log.info(s"VoyagePaxSplits ${uzfc.summary}")
      uzfc
    })

    val unzippedSink = unzipFlow.to(subscriberFlightActor)
    val i = 1

    val runOnce = UnzipGraphStage.runOnce(log)(unzippedFileProvider.latestFilePaths) _

    val onBatchReadingFinished = (tryDone: Try[Done]) => log.info(s"Reading files finished")

    runOnce(i, onBatchReadingFinished, onNewFileSeen, unzippedSink)

    batchPollProcessingDone.onComplete {
      case Success(complete) =>
        log.info(s"FilePolling complete ${complete}")
      case Failure(f) =>
        log.error(f, s"FilePolling failed ${f}")

    }
    batchPollProcessingDone
  }
}


object AtmosFilePolling {
  val log = LoggerFactory.getLogger(getClass)

  def filterToFilesNewerThan(listOfFiles: Seq[String], latestFile: String) = {
    log.info(s"filtering ${listOfFiles.length} with $latestFile")
    val regex = "(drt_dq_[0-9]{6}_[0-9]{6})(_[0-9]{4}\\.zip)".r
    val filterFrom = latestFile match {
      case regex(dateTime, _) => dateTime
      case _ => latestFile
    }
    println(s"filterFrom: $filterFrom, latestFile: $latestFile")
    listOfFiles.filter(fn => fn >= filterFrom && fn != latestFile)
  }

  def previousDayDqFilename(date: MilliDate) = {
    dqFilename(previousDay(date))
  }

  def previousDay(date: MilliDate): SDateLike = {
    val oneDayInMillis = 60 * 60 * 24 * 1000L
    val previousDay = SDate(date.millisSinceEpoch - oneDayInMillis)
    previousDay
  }

  def dqFilename(previousDay: SDateLike) = {
    val year = previousDay.getFullYear().toInt - 2000
    f"drt_dq_$year${previousDay.getMonth()}%02d${previousDay.getDate()}%02d"
  }

  def beginPolling(log: LoggingAdapter,
                   flightPassengerReporter: ActorRef,
                   initialFileFilter: String,
                   atmosHost: String,
                   bucket: String,
                   portCode: String)(
                    implicit actorSystem: ActorSystem
                    , mat: Materializer
                  ) = {
    val statefulPoller = StatefulAtmosPoller(Some(initialFileFilter), atmosHost, bucket)
    val unzippedFileProvider = statefulPoller.unzippedFileProvider

    var outLatestFile = initialFileFilter

    val source = Source.tick(1 seconds, 2 minutes, NotUsed).map((notUsed) => DateTime.now())

    implicit val materializer = ActorMaterializer()

    def getUzfc(zipFileName: String): Future[List[UnzippedFileContent]] = {
      manifestsFromZip(unzippedFileProvider, materializer, zipFileName)
    }

    val batchFileState = new BatchFileState {
      def onBatchComplete(filename: String) = outLatestFile = filename

      def latestFile = outLatestFile
    }

    source.runForeach { tickId =>
      val zipfilenamesSource = unzippedFileProvider.createBuilder.listFilesAsStream(bucket).map(_._1)
      runSingleBatch(tickId,
        zipfilenamesSource,
        getUzfc _,
        flightPassengerReporter, batchFileState
      )
    }
  }

  type UnzipFileContentFunc = (String) => Future[List[UnzippedFileContent]]

  trait BatchFileState {
    def latestFile: String

    def onBatchComplete(filename: String): Unit
  }

  def runSingleBatch(tickId: DateTime,
                     zipFilenamesSource: Source[String, NotUsed],
                     unzipFileContent: UnzipFileContentFunc,
                     flightPassengerReporter: ActorRef,
                     batchFileState: BatchFileState)
                    (implicit materializer: Materializer): Unit = {
    log.info(s"tickId: $tickId Starting batch")
    val futureZipFiles: Future[Seq[String]] = zipFilenamesSource.runWith(Sink.seq)

    for (fileNames <- futureZipFiles) {
      val latestFile = batchFileState.latestFile
      val zipFilesToProcess = filterToFilesNewerThan(fileNames, latestFile).sorted.toList
      log.info(s"tickId: ${tickId} zipFilesToProcess: ${zipFilesToProcess} since $latestFile, allFiles: ${fileNames.length} vs ${zipFilesToProcess.length}")
      zipFilesToProcess
        .foreach(zipFileName => {
          log.info(s"tickId: $tickId: latestFile: $latestFile")
          log.info(s"tickId: $tickId: AdvPaxInfo: extracting manifests from zip $zipFileName")

          val zip: Future[List[UnzippedFileContent]] = unzipFileContent(zipFileName)
          val sentMessage: Future[Unit] = zip
            .map(manifests => {
              log.info(s"tickId: $tickId processing manifests from zip '$zipFileName'. Length: ${manifests.length}, Content: ${manifests.map(_.filename)}")
              manifestsToAdvPaxReporter(log, flightPassengerReporter, manifests)
              log.info(s"tickId: $tickId processed manifests from zip '$zipFileName': Length ${manifests.length}  ${manifests.headOption.map(_.filename)}")
              //              statefulPoller.onNewFileSeen(zipFileName)

            })

          log.info(s"AdvPaxInfo: tickId: ${tickId} updating latestFile: ${latestFile} to ${zipFileName}")
          batchFileState.onBatchComplete(zipFileName)

          log.info(s"AdvPaxInfo: tickId: ${tickId} finished processing zip $zipFileName $latestFile")
        })
    }
  }

  private def manifestsFromZip(unzippedFileProvider: SimpleAtmosReader, materializer: ActorMaterializer, zipFileName: String) = {
    unzippedFileProvider.zipFilenameToEventualFileContent(zipFileName)(materializer, scala.concurrent.ExecutionContext.global)
  }

  private def manifestsToAdvPaxReporter(log: Logger, advPaxReporter: ActorRef, manifests: List[ZipUtils.UnzippedFileContent]) = {
    log.info(s"AdvPaxInfo: parsing ${manifests.length} manifests")
    manifests.foreach((flightManifest) => {
      log.info(s"AdvPaxInfo: manifest ${flightManifest.filename} from ${flightManifest.zipFilename}")
      VoyagePassengerInfoParser.parseVoyagePassengerInfo(flightManifest.content) match {
        case Success(vpi) =>
          advPaxReporter ! vpi
        case Failure(f) =>
          log.warn(s"Failed to parse voyage passenger info: From ${flightManifest.filename} in ${flightManifest.zipFilename}, error: $f")
      }
    })
  }
}
