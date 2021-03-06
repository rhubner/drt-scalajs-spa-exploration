package services.graphstages

import akka.stream._
import akka.stream.stage.{GraphStage, GraphStageLogic, InHandler, OutHandler}
import drt.shared.CrunchApi.{CrunchMinute, CrunchMinutes, MillisSinceEpoch}
import drt.shared.FlightsApi.{QueueName, TerminalName}
import drt.shared._
import org.slf4j.{Logger, LoggerFactory}
import services.graphstages.Crunch._
import services.{OptimizerConfig, OptimizerCrunchResult, SDate}

import scala.collection.immutable.Map
import scala.language.postfixOps
import scala.util.{Failure, Success, Try}


class CrunchLoadGraphStage(optionalInitialCrunchMinutes: Option[CrunchMinutes],
                           airportConfig: AirportConfig,
                           expireAfterMillis: MillisSinceEpoch,
                           now: () => SDateLike,
                           crunch: (Seq[Double], Seq[Int], Seq[Int], OptimizerConfig) => Try[OptimizerCrunchResult])
  extends GraphStage[FlowShape[Loads, CrunchMinutes]] {

  val inLoads: Inlet[Loads] = Inlet[Loads]("inLoads.in")
  val outCrunchMinutes: Outlet[CrunchMinutes] = Outlet[CrunchMinutes]("outCrunchMinutes.out")

  override val shape = new FlowShape(inLoads, outCrunchMinutes)

  override def createLogic(inheritedAttributes: Attributes): GraphStageLogic = new GraphStageLogic(shape) {
    var loadMinutes: Map[Int, LoadMinute] = Map()
    var existingCrunchMinutes: Map[Int, CrunchMinute] = Map()
    var crunchMinutesToPush: Map[Int, CrunchMinute] = Map()

    val log: Logger = LoggerFactory.getLogger(getClass)

    override def preStart(): Unit = {
      loadMinutes = optionalInitialCrunchMinutes match {
        case None => Map()
        case Some(CrunchMinutes(cms)) => cms.map(cm => {
          val lm = LoadMinute(cm.terminalName, cm.queueName, cm.paxLoad, cm.workLoad, cm.minute)
          (lm.uniqueId, lm)
        }).toMap
      }

      super.preStart()
    }

    setHandler(inLoads, new InHandler {
      override def onPush(): Unit = {
        val incomingLoads = grab(inLoads)
        log.info(s"Received ${incomingLoads.loadMinutes.size} loads")
        
        val allMinuteMillis = incomingLoads.loadMinutes.map(_.minute)
        val firstMinute = Crunch.getLocalLastMidnight(SDate(allMinuteMillis.min))
        val lastMinute = Crunch.getLocalNextMidnight(SDate(allMinuteMillis.max))
        log.info(s"Crunch ${firstMinute.toLocalDateTimeString()} - ${lastMinute.toLocalDateTimeString()}")

        val updatedLoads: Map[Int, LoadMinute] = mergeLoads(incomingLoads.loadMinutes, loadMinutes)
        loadMinutes = Crunch.purgeExpired(updatedLoads, (lm: LoadMinute) => lm.minute, now, expireAfterMillis)

        val crunchMinutes: Set[CrunchMinute] = crunchLoads(firstMinute.millisSinceEpoch, lastMinute.millisSinceEpoch, loadMinutes.values.toSet)
        val crunchMinutesByKey = crunchMinutes.map(cm => (cm.key, cm)).toMap

        val diff = crunchMinutes -- existingCrunchMinutes.values.toSet

        existingCrunchMinutes = Crunch.purgeExpired(crunchMinutesByKey, (cm: CrunchMinute) => cm.minute, now, expireAfterMillis)

        val mergedCrunchMinutes = mergeCrunchMinutes(diff, crunchMinutesToPush)
        crunchMinutesToPush = purgeExpired(mergedCrunchMinutes, (cm: CrunchMinute) => cm.minute, now, expireAfterMillis)
        log.info(s"Now have ${crunchMinutesToPush.size} load minutes to push")

        pushStateIfReady()

        pullLoads()
      }
    })

    def crunchLoads(firstMinute: MillisSinceEpoch, lastMinute: MillisSinceEpoch, loads: Set[LoadMinute]): Set[CrunchMinute] = {
      loads
        .filter(lm => firstMinute <= lm.minute && lm.minute < lastMinute)
        .groupBy(_.terminalName)
        .flatMap {
          case (tn, tLms) => tLms
            .groupBy(_.queueName)
            .flatMap {
              case (qn, qLms) =>
                log.info(s"Crunching $tn $qn")
                val sla = airportConfig.slaByQueue.getOrElse(qn, 15)
                val sortedLms = qLms.toSeq.sortBy(_.minute)
                val workMinutes: Map[MillisSinceEpoch, Double] = sortedLms.map(m => (m.minute, m.workLoad)).toMap
                val paxMinutes: Map[MillisSinceEpoch, Double] = sortedLms.map(m => (m.minute, m.paxLoad)).toMap
                val minuteMillis = firstMinute until lastMinute by 60000
                val fullWorkMinutes = minuteMillis.map(m => workMinutes.getOrElse(m, 0d))
                val fullPaxMinutes = minuteMillis.map(m => paxMinutes.getOrElse(m, 0d))
                val (minDesks, maxDesks) = minMaxDesksForQueue(minuteMillis, tn, qn)
                val triedResult: Try[OptimizerCrunchResult] = crunch(fullWorkMinutes, minDesks, maxDesks, OptimizerConfig(sla))
                triedResult match {
                  case Success(OptimizerCrunchResult(desks, waits)) =>
                    minuteMillis.zipWithIndex.map {
                      case (minute, idx) =>
                        val wl = fullWorkMinutes(idx)
                        val pl = fullPaxMinutes(idx)
                        CrunchMinute(tn, qn, minute, pl, wl, desks(idx), waits(idx))
                    }
                  case Failure(t) =>
                    log.warn(s"failed to crunch: $t")
                    Set()
                }
            }
        }.toSet
    }

    def minMaxDesksForQueue(crunchMinutes: Seq[MillisSinceEpoch], tn: TerminalName, qn: QueueName): (Seq[Int], Seq[Int]) = {
      val defaultMinMaxDesks = (Seq.fill(24)(0), Seq.fill(24)(10))
      val queueMinMaxDesks = airportConfig.minMaxDesksByTerminalQueue.getOrElse(tn, Map()).getOrElse(qn, defaultMinMaxDesks)
      val minDesks = crunchMinutes.map(desksForHourOfDayInUKLocalTime(_, queueMinMaxDesks._1))
      val maxDesks = crunchMinutes.map(desksForHourOfDayInUKLocalTime(_, queueMinMaxDesks._2))
      (minDesks, maxDesks)
    }

    def mergeCrunchMinutes(updatedCms: Set[CrunchMinute], existingCms: Map[Int, CrunchMinute]): Map[Int, CrunchMinute] = {
      updatedCms.foldLeft(existingCms) {
        case (soFar, newLoadMinute) => soFar.updated(newLoadMinute.key, newLoadMinute)
      }
    }

    def loadDiff(updatedLoads: Set[LoadMinute], existingLoads: Set[LoadMinute]): Set[LoadMinute] = {
      val loadDiff = updatedLoads -- existingLoads
      log.info(s"${loadDiff.size} updated load minutes")

      loadDiff
    }

    def mergeLoads(incomingLoads: Set[LoadMinute], existingLoads: Map[Int, LoadMinute]): Map[Int, LoadMinute] = {
      incomingLoads.foldLeft(existingLoads) {
        case (soFar, load) =>
          soFar.updated(load.uniqueId, load)
      }
    }

    setHandler(outCrunchMinutes, new OutHandler {
      override def onPull(): Unit = {
        log.debug(s"outLoads onPull called")
        pushStateIfReady()
        pullLoads()
      }
    })

    def pullLoads(): Unit = {
      if (!hasBeenPulled(inLoads)) {
        log.info(s"Pulling inFlightsWithSplits")
        pull(inLoads)
      }
    }

    def pushStateIfReady(): Unit = {
      if (crunchMinutesToPush.isEmpty) log.info(s"We have no crunch minutes. Nothing to push")
      else if (isAvailable(outCrunchMinutes)) {
        log.info(s"Pushing ${crunchMinutesToPush.size} crunch minutes")
        push(outCrunchMinutes, CrunchMinutes(crunchMinutesToPush.values.toSet))
        crunchMinutesToPush = Map()
      } else log.info(s"outCrunchMinutes not available to push")
    }
  }
}
