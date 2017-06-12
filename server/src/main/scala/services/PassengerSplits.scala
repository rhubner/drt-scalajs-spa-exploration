package services

import akka.pattern.AskableActorRef
import akka.util.Timeout
import com.typesafe.config.{Config, ConfigFactory}
import drt.shared.PassengerSplits.{FlightNotFound, VoyagePaxSplits}
import drt.shared.SplitRatiosNs.{SplitRatio, SplitRatios}
import drt.shared.{AirportConfig, Arrival, FlightParsing, PaxTypeAndQueue}
import org.slf4j.LoggerFactory
import passengersplits.core.PassengerInfoRouterActor.ReportVoyagePaxSplit

import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext}

object AdvPaxSplitsProvider {
  val log = LoggerFactory.getLogger(getClass)

  def splitRatioProvider(destinationPort: String)
                        (passengerInfoRouterActor: AskableActorRef)
                        (flight: Arrival)
                        (implicit timeOut: Timeout, ec: ExecutionContext): Option[SplitRatios] = {
    log.debug(s"${flight.IATA} splitRatioProvider")
    FlightParsing.parseIataToCarrierCodeVoyageNumber(flight.IATA) match {
      case Some((cc, number)) =>
        val splitRequest = ReportVoyagePaxSplit(flight.AirportID, flight.Operator, number, SDate(flight.SchDT))

        def logSr(mm: => String) = log.info(s"$splitRequest $mm")

        logSr("sending request")
        val futResp = passengerInfoRouterActor ? splitRequest
        val splitsFut = futResp.map {
          case voyagePaxSplits: VoyagePaxSplits =>
            log.info(s"${flight.IATA} didgotsplitcrunch")
            Some(convertVoyagePaxSplitPeopleCountsToSplitRatios(voyagePaxSplits))
          case _: FlightNotFound =>
            log.debug(s"${flight.IATA} notgotsplitcrunch")
            None
        }
        splitsFut.onFailure {
          case t: Throwable =>
            log.error(s"Failure to get splits in crunch for $flight ", t)
        }
        //todo - kill this await by surfacing a future instead.
        Await.result(splitsFut, FiniteDuration(10, SECONDS))
      case _ =>
        log.error(s"Flight does not have IATA code $flight")
        None
    }
  }


  def splitRatioProviderWithCsvPercentages(destinationPort: String)
                                          (passengerInfoRouterActor: AskableActorRef)
                                          (egatePercentageProvider: (Arrival) => Double,
                                           fastTrackPercentageProvider: (Arrival) => Option[FastTrackPercentages])
                                          (flight: Arrival)
                                          (implicit timeOut: Timeout, ec: ExecutionContext): Option[SplitRatios] = {
    log.debug(s"${flight.IATA} splitRatioProviderWithCsvEgatepercentage")
    FlightParsing.parseIataToCarrierCodeVoyageNumber(flight.IATA) match {
      case Some((cc, number)) =>
        val splitRequest = ReportVoyagePaxSplit(flight.AirportID, flight.Operator, number, SDate(flight.SchDT))

        def logSr(mm: => String) = log.debug(s"$splitRequest $mm")

        logSr("sending request")
        val futResp = passengerInfoRouterActor ? splitRequest //todo should this just be a (SplitRequest) => Either[FlightNotFound, VoyagePaxSplits], might be slightly simple in tests, and a bit more flexible?
        val splitsFut = futResp.map {
          case voyagePaxSplits: VoyagePaxSplits =>
            logSr(s"${flight.IATA} didgotsplitcrunch")
            val egatePercentage = egatePercentageProvider(flight)
            val voyagePaxSplitsWithEgatePercentage = CSVPassengerSplitsProvider.applyEgates(voyagePaxSplits, egatePercentage)
            val fastTrackPercentages = fastTrackPercentageProvider(flight)
            val withFastTrack = fastTrackPercentages match {
              case Some(fastTrackPercentages) => CSVPassengerSplitsProvider.applyFastTrack (voyagePaxSplits, fastTrackPercentages = fastTrackPercentages)
              case None => voyagePaxSplitsWithEgatePercentage
            }
            logSr(s"applying egate percentage $egatePercentage to $voyagePaxSplits")
            logSr(s"applied egate percentage $egatePercentage => $voyagePaxSplitsWithEgatePercentage")
            logSr(s"applied fasttrack percentage $fastTrackPercentages => $withFastTrack")
            Some(convertVoyagePaxSplitPeopleCountsToSplitRatios(withFastTrack))
          case _: FlightNotFound =>
            log.debug(s"${flight.IATA} notgotsplitcrunch")
            None
        }
        splitsFut.onFailure {
          case t: Throwable =>
            log.error(s"Failure to get splits in crunch for $flight ", t)
        }
        //todo - kill this await by surfacing a future instead.
        Await.result(splitsFut, FiniteDuration(10, SECONDS))
      case _ =>
        log.error(s"Flight does not have IATA code $flight")
        None
    }
  }

  def convertVoyagePaxSplitPeopleCountsToSplitRatios(splits: VoyagePaxSplits) = {
    SplitRatios(splits.paxSplits
      .map(split => SplitRatio(
        PaxTypeAndQueue(split), split.paxCount.toDouble / splits.totalPaxCount)), origin = "AdvancedPaxInfo")
  }

}

object SplitsProvider {
  type SplitProvider = (Arrival) => Option[SplitRatios]
  val log = LoggerFactory.getLogger(getClass)

  def splitsForFlight(providers: List[SplitProvider])(apiFlight: Arrival): Option[SplitRatios] = {
    providers.foldLeft(None: Option[SplitRatios])((prev, provider) => {
      prev match {
        case Some(split) => prev
        case None => provider(apiFlight)
      }
    })
  }

  def shouldUseCsvSplitsProvider: Boolean = {
    val config: Config = ConfigFactory.load
    log.info(s"splitsProvider: csv path ${config.getString("passenger_splits_csv_url")}")
    config.hasPath("passenger_splits_csv_url") && config.getString("passenger_splits_csv_url") != ""
  }

  def emptyProvider: SplitProvider = _ => Option.empty[SplitRatios]

  def csvProvider: SplitProvider = {
    if (shouldUseCsvSplitsProvider) {
      log.info("SplitsProvider: Using csv splits provider")
      CSVPassengerSplitsProvider(CsvPassengerSplitsReader.flightPaxSplitsLinesFromConfig).splitRatioProvider
    }
    else {
      log.info("SplitsProvider: using emptyProvider")
      emptyProvider
    }
  }

  def defaultProvider(airportConf: AirportConfig): (Arrival) => Some[SplitRatios] = {
    _ => Some(airportConf.defaultPaxSplits)
  }

}

