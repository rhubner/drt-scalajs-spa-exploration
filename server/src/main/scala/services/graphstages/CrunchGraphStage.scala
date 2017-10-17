package services.graphstages

import akka.stream.stage.{GraphStage, GraphStageLogic, InHandler, OutHandler}
import akka.stream.{Attributes, FanInShape2, Inlet, Outlet}
import controllers.SystemActors.SplitsProvider
import drt.shared.Crunch.{CrunchMinute, MillisSinceEpoch, PortState}
import drt.shared.FlightsApi.{FlightsWithSplits, QueueName, TerminalName}
import drt.shared.PassengerSplits.{PaxTypeAndQueueCounts, SplitsPaxTypeAndQueueCount}
import drt.shared.PaxTypes.{EeaMachineReadable, NonVisaNational, VisaNational}
import drt.shared.Queues.{EGate, EeaDesk}
import drt.shared.SplitRatiosNs.{SplitRatio, SplitRatios, SplitSources}
import drt.shared._
import org.slf4j.{Logger, LoggerFactory}
import passengersplits.core.PassengerQueueCalculator
import passengersplits.parsing.VoyageManifestParser.{VoyageManifest, VoyageManifests}
import services.graphstages.Crunch._
import services.workloadcalculator.PaxLoadCalculator.Load
import services.{FastTrackPercentages, SDate}

import scala.collection.immutable.{Map, Seq}
import scala.language.postfixOps

case class ArrivalsDiff(toUpdate: Set[Arrival], toRemove: Set[Int])

class CrunchGraphStage(name: String,
                       optionalInitialFlights: Option[FlightsWithSplits],
                       slas: Map[QueueName, Int],
                       minMaxDesks: Map[TerminalName, Map[QueueName, (List[Int], List[Int])]],
                       procTimes: Map[PaxTypeAndQueue, Double],
                       groupFlightsByCodeShares: (Seq[ApiFlightWithSplits]) => List[(ApiFlightWithSplits, Set[Arrival])],
                       portSplits: SplitRatios,
                       csvSplitsProvider: SplitsProvider,
                       crunchStartFromFirstPcp: (SDateLike) => SDateLike = getLocalLastMidnight,
                       crunchEndFromLastPcp: (SDateLike) => SDateLike = (_) => getLocalNextMidnight(SDate.now()),
                       earliestAndLatestAffectedPcpTime: (Set[ApiFlightWithSplits], Set[ApiFlightWithSplits]) => Option[(SDateLike, SDateLike)])
  extends GraphStage[FanInShape2[ArrivalsDiff, VoyageManifests, PortState]] {

  val inArrivalsDiff: Inlet[ArrivalsDiff] = Inlet[ArrivalsDiff]("ArrivalsDiffIn.in")
  val inManifests: Inlet[VoyageManifests] = Inlet[VoyageManifests]("SplitsIn.in")
  val outCrunch: Outlet[PortState] = Outlet[PortState]("PortStateOut.out")
  override val shape = new FanInShape2(inArrivalsDiff, inManifests, outCrunch)

  override def createLogic(inheritedAttributes: Attributes): GraphStageLogic = new GraphStageLogic(shape) {
    var flightsByFlightId: Map[Int, ApiFlightWithSplits] = Map()
    var manifestsBuffer: Map[String, Set[VoyageManifest]] = Map()
    var waitingForArrivals = true
    var waitingForManifests = true

    var portStateOption: Option[PortState] = None

    val log: Logger = LoggerFactory.getLogger(s"$getClass-$name")

    override def preStart(): Unit = {
      optionalInitialFlights match {
        case Some(FlightsWithSplits(flights)) =>
          log.info(s"Received initial flights. Setting ${flights.size}")
          flightsByFlightId = flights.map(f => Tuple2(f.apiFlight.uniqueId, f)).toMap
        case _ =>
          log.warn(s"Did not receive any flights to initialise with")
      }
      super.preStart()
    }

    setHandler(outCrunch, new OutHandler {
      override def onPull(): Unit = {
        log.debug(s"crunchOut onPull called")
        if (!waitingForManifests && !waitingForArrivals) {
          portStateOption match {
            case Some(portState) =>
              log.debug(s"Pushing PortState")
              push(outCrunch, portState)
              portStateOption = None
            case None =>
              log.debug(s"No PortState to push")
          }
        } else {
          if (waitingForArrivals) log.info(s"Waiting for arrivals")
          if (waitingForManifests) log.info(s"Waiting for manifests")
        }
        if (!hasBeenPulled(inManifests)) pull(inManifests)
        if (!hasBeenPulled(inArrivalsDiff)) pull(inArrivalsDiff)
      }
    })

    setHandler(inArrivalsDiff, new InHandler {
      override def onPush(): Unit = {
        log.debug(s"inFlights onPush called")
        val arrivalsDiff = grab(inArrivalsDiff)
        waitingForArrivals = false

        log.info(s"Grabbed ${arrivalsDiff.toUpdate.size} updates, ${arrivalsDiff.toRemove.size} removals")
        val updatedFlights = updateFlightsFromIncoming(arrivalsDiff, flightsByFlightId)

        if (flightsByFlightId != updatedFlights) {
          crunchIfAppropriate(updatedFlights, flightsByFlightId)
          flightsByFlightId = updatedFlights
        } else log.info(s"No flight updates")

        if (!hasBeenPulled(inArrivalsDiff)) pull(inArrivalsDiff)
      }
    })

    setHandler(inManifests, new InHandler {
      override def onPush(): Unit = {
        log.debug(s"inSplits onPush called")
        val vms = grab(inManifests)
        waitingForManifests = false

        log.info(s"Grabbed ${vms.manifests.size} manifests")
        val updatedFlights = updateFlightsWithManifests(vms.manifests, flightsByFlightId)

        if (flightsByFlightId != updatedFlights) {
          crunchIfAppropriate(updatedFlights, flightsByFlightId)
          flightsByFlightId = updatedFlights
        } else log.info(s"No splits updates")

        if (!hasBeenPulled(inManifests)) pull(inManifests)
      }
    })

    def crunchIfAppropriate(updatedFlights: Map[Int, ApiFlightWithSplits], existingFlights: Map[Int, ApiFlightWithSplits]): Unit = {
      val earliestAndLatest = earliestAndLatestAffectedPcpTime(existingFlights.values.toSet, updatedFlights.values.toSet)
      log.info(s"Latest PCP times: $earliestAndLatest")
      earliestAndLatest.foreach {
        case (earliest, latest) =>
          val crunchStart = crunchStartFromFirstPcp(earliest)
          val crunchEnd = crunchEndFromLastPcp(latest)
          log.info(s"Crunch period ${crunchStart.toLocalDateTimeString()} to ${crunchEnd.toLocalDateTimeString()}")
          portStateOption = crunch(updatedFlights, crunchStart, crunchEnd)
          pushStateIfReady()
      }
    }

    def updateFlightsFromIncoming(arrivalsDiff: ArrivalsDiff, existingFlightsById: Map[Int, ApiFlightWithSplits]): Map[Int, ApiFlightWithSplits] = {
      log.info(s"${arrivalsDiff.toUpdate.size} diff updates, ${existingFlightsById.size} existing flights")
      val afterRemovals = existingFlightsById.filterNot {
        case (id, _) => arrivalsDiff.toRemove.contains(id)
      }
      val updatedFlights = arrivalsDiff.toUpdate.foldLeft[Map[Int, ApiFlightWithSplits]](afterRemovals) {
        case (flightsSoFar, updatedFlight) =>
          flightsSoFar.get(updatedFlight.uniqueId) match {
            case None =>
              log.info(s"Adding new flight ${updatedFlight.IATA} / ${updatedFlight.SchDT} with key ${updatedFlight.uniqueId}")
              val ths = terminalAndHistoricSplits(updatedFlight)
              val newFlightWithSplits = ApiFlightWithSplits(updatedFlight, ths, Option(SDate.now().millisSinceEpoch))
              val newFlightWithAvailableSplits = addApiSplitsIfAvailable(newFlightWithSplits)
              flightsSoFar.updated(updatedFlight.uniqueId, newFlightWithAvailableSplits)

            case Some(existingFlight) if existingFlight.apiFlight != updatedFlight =>
              log.info(s"Updating flight ${updatedFlight.IATA}. PcpTime ${updatedFlight.PcpTime} -> ${updatedFlight.PcpTime}")
              flightsSoFar.updated(updatedFlight.uniqueId, existingFlight.copy(apiFlight = updatedFlight))

            case _ => flightsSoFar
          }
      }
      log.info(s"${updatedFlights.size} flights after updates")
      updatedFlights
    }

    def addApiSplitsIfAvailable(newFlightWithSplits: ApiFlightWithSplits): ApiFlightWithSplits = {
      val arrival = newFlightWithSplits.apiFlight
      val vmIdx = s"${Crunch.flightVoyageNumberPadded(arrival)}-${arrival.Scheduled}"

      val newFlightWithAvailableSplits = manifestsBuffer.get(vmIdx) match {
        case None => newFlightWithSplits
        case Some(vm) =>
          log.info(s"Found buffered manifest to apply to new flight")
          manifestsBuffer = manifestsBuffer.filterNot { case (idx, _) => idx == vmIdx }
          log.info(s"Removed applied manifest from buffer")
          removeManifestsOlderThan(twoDaysAgo)
          updateFlightWithManifests(vm, newFlightWithSplits)
      }
      newFlightWithAvailableSplits
    }

    def removeManifestsOlderThan(thresholdMillis: MillisSinceEpoch): Unit = {
      manifestsBuffer = manifestsBuffer.filter {
        case (_, vmsInBuffer) =>
          val vmsToKeep = vmsInBuffer.filter(vm => isNewerThan(thresholdMillis, vm))
          vmsToKeep match {
            case vms if vms.nonEmpty => true
            case _ => false
          }
      }
    }

    def updateFlightsWithManifests(manifests: Set[VoyageManifest], flightsById: Map[Int, ApiFlightWithSplits]): Map[Int, ApiFlightWithSplits] = {
      manifests.foldLeft[Map[Int, ApiFlightWithSplits]](flightsByFlightId) {
        case (flightsSoFar, newManifest) =>
          val vmMillis = newManifest.scheduleArrivalDateTime match {
            case None => 0L
            case Some(scheduled) => scheduled.millisSinceEpoch
          }
          val matchingFlight: Option[(Int, ApiFlightWithSplits)] = flightsSoFar
            .find {
              case (_, f) =>
                val vnMatches = Crunch.flightVoyageNumberPadded(f.apiFlight) == newManifest.VoyageNumber
                val schMatches = vmMillis == f.apiFlight.Scheduled
                vnMatches && schMatches
              case _ => false
            }

          matchingFlight match {
            case None =>
              log.info(s"Stashing VoyageManifest in case flight is seen later")
              val idx = s"${newManifest.VoyageNumber}-$vmMillis"
              val existingManifests = manifestsBuffer.getOrElse(idx, Set())
              val updatedManifests = existingManifests + newManifest
              manifestsBuffer = manifestsBuffer.updated(idx, updatedManifests)
              flightsSoFar
            case Some(Tuple2(id, f)) =>
              val updatedFlight = updateFlightWithManifest(f, newManifest)
              flightsSoFar.updated(id, updatedFlight)
          }
      }
    }

    def crunch(flights: Map[Int, ApiFlightWithSplits], crunchStart: SDateLike, crunchEnd: SDateLike): Option[PortState] = {
      val flightsInCrunchWindow = flights.values.toList.filter(f => isFlightInTimeWindow(f, crunchStart, crunchEnd))
      log.info(s"Requesting crunch for ${flightsInCrunchWindow.length} flights after flights update")
      val uniqueFlights = groupFlightsByCodeShares(flightsInCrunchWindow).map(_._1)
      log.info(s"${uniqueFlights.length} unique flights after filtering for code shares")
      val newFlightsById = uniqueFlights.map(f => (f.apiFlight.uniqueId, f)).toMap
      val newFlightSplitMinutesByFlight = flightsToFlightSplitMinutes(procTimes)(uniqueFlights)
      val numberOfMinutes = ((crunchEnd.millisSinceEpoch - crunchStart.millisSinceEpoch) / 60000).toInt
      log.info(s"Crunching $numberOfMinutes minutes")
      val crunchMinutes = crunchMinutesFromFlightSplitMinutes(crunchStart.millisSinceEpoch, numberOfMinutes, newFlightsById, newFlightSplitMinutesByFlight)

      Option(PortState(flights, crunchMinutes))
    }

    def pushStateIfReady(): Unit = {
      if (!waitingForManifests && !waitingForArrivals) {
        portStateOption match {
          case None => log.info(s"We have no PortState yet. Nothing to push")
          case Some(portState) =>
            if (isAvailable(outCrunch)) {
              log.info(s"Pushing PortState")
              push(outCrunch, portState)
              portStateOption = None
            }
        }
      } else {
        if (waitingForArrivals) log.info(s"Waiting for arrivals")
        if (waitingForManifests) log.info(s"Waiting for manifests")
      }
    }

    def crunchMinutesFromFlightSplitMinutes(crunchStart: MillisSinceEpoch,
                                            numberOfMinutes: Int,
                                            flightsById: Map[Int, ApiFlightWithSplits],
                                            fsmsByFlightId: Map[Int, Set[FlightSplitMinute]]): Map[Int, CrunchMinute] = {
      val crunchResults: Map[Int, CrunchMinute] = crunchFlightSplitMinutes(crunchStart, numberOfMinutes, fsmsByFlightId)

      crunchResults
    }

    def crunchFlightSplitMinutes(crunchStart: MillisSinceEpoch, numberOfMinutes: Int, flightSplitMinutesByFlight: Map[Int, Set[FlightSplitMinute]]): Map[Int, CrunchMinute] = {
      val qlm: Set[QueueLoadMinute] = flightSplitMinutesToQueueLoadMinutes(flightSplitMinutesByFlight)
      val wlByQueue: Map[TerminalName, Map[QueueName, Map[MillisSinceEpoch, (Load, Load)]]] = indexQueueWorkloadsByMinute(qlm)

      val fullWlByQueue: Map[TerminalName, Map[QueueName, List[(MillisSinceEpoch, (Load, Load))]]] = queueMinutesForPeriod(crunchStart, numberOfMinutes)(wlByQueue)
      val eGateBankSize = 5

      val crunchResults = workloadsToCrunchMinutes(crunchStart, numberOfMinutes, fullWlByQueue, slas, minMaxDesks, eGateBankSize)
      crunchResults
    }

    def terminalAndHistoricSplits(fs: Arrival): Set[ApiSplits] = {
      val historical: Option[Set[ApiPaxTypeAndQueueCount]] = historicalSplits(fs)
      val splitRatios: Set[SplitRatio] = portSplits.splits.toSet
      val portDefault: Set[ApiPaxTypeAndQueueCount] = splitRatios.map {
        case SplitRatio(ptqc, ratio) => ApiPaxTypeAndQueueCount(ptqc.passengerType, ptqc.queueType, ratio)
      }

      val defaultSplits = Set(ApiSplits(portDefault.map(aptqc => aptqc.copy(paxCount = aptqc.paxCount * 100)), SplitSources.TerminalAverage, None, Percentage))

      historical match {
        case None => defaultSplits
        case Some(h) => Set(ApiSplits(h, SplitSources.Historical, None, Percentage)) ++ defaultSplits
      }
    }

    def historicalSplits(fs: Arrival): Option[Set[ApiPaxTypeAndQueueCount]] = {
      csvSplitsProvider(fs).map(ratios => {
        val splitRatios: Set[SplitRatio] = ratios.splits.toSet
        splitRatios.map {
          case SplitRatio(ptqc, ratio) => ApiPaxTypeAndQueueCount(ptqc.passengerType, ptqc.queueType, ratio * 100)
        }
      })
    }

    def fastTrackPercentagesFromSplit(splitOpt: Option[SplitRatios], defaultVisaPct: Double, defaultNonVisaPct: Double): FastTrackPercentages = {
      val visaNational = splitOpt
        .map {
          ratios =>

            val splits = ratios.splits
            val visaNationalSplits = splits.filter(s => s.paxType.passengerType == PaxTypes.VisaNational)

            val totalVisaNationalSplit = visaNationalSplits.map(_.ratio).sum

            splits
              .find(p => p.paxType.passengerType == PaxTypes.VisaNational && p.paxType.queueType == Queues.FastTrack)
              .map(_.ratio / totalVisaNationalSplit).getOrElse(defaultVisaPct)
        }.getOrElse(defaultVisaPct)

      val nonVisaNational = splitOpt
        .map {
          ratios =>
            val splits = ratios.splits
            val totalNonVisaNationalSplit = splits.filter(s => s.paxType.passengerType == PaxTypes.NonVisaNational).map(_.ratio).sum

            splits
              .find(p => p.paxType.passengerType == PaxTypes.NonVisaNational && p.paxType.queueType == Queues.FastTrack)
              .map(_.ratio / totalNonVisaNationalSplit).getOrElse(defaultNonVisaPct)
        }.getOrElse(defaultNonVisaPct)
      FastTrackPercentages(visaNational, nonVisaNational)
    }

    def egatePercentageFromSplit(splitOpt: Option[SplitRatios], defaultPct: Double): Double = {
      splitOpt
        .map { x =>
          val splits = x.splits
          val interestingSplits = splits.filter(s => s.paxType.passengerType == PaxTypes.EeaMachineReadable)
          val interestingSplitsTotal = interestingSplits.map(_.ratio).sum
          splits
            .find(p => p.paxType.queueType == Queues.EGate)
            .map(_.ratio / interestingSplitsTotal).getOrElse(defaultPct)
        }.getOrElse(defaultPct)
    }

    def applyEgatesSplits(ptaqc: Set[ApiPaxTypeAndQueueCount], egatePct: Double): Set[ApiPaxTypeAndQueueCount] = {
      ptaqc.flatMap {
        case s@ApiPaxTypeAndQueueCount(EeaMachineReadable, EeaDesk, count) =>
          val eeaDeskPax = Math.round(count * (1 - egatePct)).toInt
          s.copy(queueType = EGate, paxCount = count - eeaDeskPax) ::
            s.copy(queueType = EeaDesk, paxCount = eeaDeskPax) :: Nil
        case s => s :: Nil
      }
    }

    def applyFastTrackSplits(ptaqc: Set[ApiPaxTypeAndQueueCount], fastTrackPercentages: FastTrackPercentages): Set[ApiPaxTypeAndQueueCount] = {
      val results = ptaqc.flatMap {
        case s@ApiPaxTypeAndQueueCount(NonVisaNational, Queues.NonEeaDesk, count) if fastTrackPercentages.nonVisaNational != 0 =>
          val nonVisaNationalNonEeaDesk = Math.round(count * (1 - fastTrackPercentages.nonVisaNational)).toInt
          s.copy(queueType = Queues.FastTrack, paxCount = count - nonVisaNationalNonEeaDesk) ::
            s.copy(paxCount = nonVisaNationalNonEeaDesk) :: Nil
        case s@ApiPaxTypeAndQueueCount(VisaNational, Queues.NonEeaDesk, count) if fastTrackPercentages.visaNational != 0 =>
          val visaNationalNonEeaDesk = Math.round(count * (1 - fastTrackPercentages.visaNational)).toInt
          s.copy(queueType = Queues.FastTrack, paxCount = count - visaNationalNonEeaDesk) ::
            s.copy(paxCount = visaNationalNonEeaDesk) :: Nil
        case s => s :: Nil
      }
      log.debug(s"applied fastTrack $fastTrackPercentages got $ptaqc")
      results
    }

    def updateFlightWithManifests(manifests: Set[VoyageManifest], f: ApiFlightWithSplits): ApiFlightWithSplits = {
      manifests.foldLeft(f) {
        case (flightSoFar, manifest) => updateFlightWithManifest(flightSoFar, manifest)
      }
    }

    def updateFlightWithManifest(flightSoFar: ApiFlightWithSplits, manifest: VoyageManifest): ApiFlightWithSplits = {
      val splitsFromManifest = paxTypeAndQueueCounts(manifest, flightSoFar)

      val updatedSplitsSet = flightSoFar.splits.filterNot {
        case ApiSplits(_, SplitSources.ApiSplitsWithCsvPercentage, Some(manifest.EventCode), _) => true
        case _ => false
      } + splitsFromManifest

      flightSoFar.copy(splits = updatedSplitsSet)
    }

    def paxTypeAndQueueCounts(manifest: VoyageManifest, f: ApiFlightWithSplits): ApiSplits = {
      val paxTypeAndQueueCounts: PaxTypeAndQueueCounts = PassengerQueueCalculator.convertVoyageManifestIntoPaxTypeAndQueueCounts(manifest)
      val sptqc: Set[SplitsPaxTypeAndQueueCount] = paxTypeAndQueueCounts.toSet
      val apiPaxTypeAndQueueCounts: Set[ApiPaxTypeAndQueueCount] = sptqc.map(ptqc => ApiPaxTypeAndQueueCount(ptqc.passengerType, ptqc.queueType, ptqc.paxCount))
      val withEgateAndFastTrack = addEgatesAndFastTrack(f, apiPaxTypeAndQueueCounts)
      val splitsFromManifest = ApiSplits(withEgateAndFastTrack, SplitSources.ApiSplitsWithCsvPercentage, Some(manifest.EventCode), PaxNumbers)

      splitsFromManifest
    }

    def addEgatesAndFastTrack(f: ApiFlightWithSplits, apiPaxTypeAndQueueCounts: Set[ApiPaxTypeAndQueueCount]): Set[ApiPaxTypeAndQueueCount] = {
      val csvSplits = csvSplitsProvider(f.apiFlight)
      val egatePercentage: Load = egatePercentageFromSplit(csvSplits, 0.6)
      val fastTrackPercentages: FastTrackPercentages = fastTrackPercentagesFromSplit(csvSplits, 0d, 0d)
      val ptqcWithCsvEgates = applyEgatesSplits(apiPaxTypeAndQueueCounts, egatePercentage)
      val ptqcwithCsvEgatesFastTrack = applyFastTrackSplits(ptqcWithCsvEgates, fastTrackPercentages)
      ptqcwithCsvEgatesFastTrack
    }
  }

  def isFlightInTimeWindow(f: ApiFlightWithSplits, crunchStart: SDateLike, crunchEnd: SDateLike): Boolean = {
    crunchStart.millisSinceEpoch <= f.apiFlight.PcpTime && f.apiFlight.PcpTime < crunchEnd.millisSinceEpoch
  }

  def isNewerThan(thresholdMillis: MillisSinceEpoch, vm: VoyageManifest): Boolean = {
    vm.scheduleArrivalDateTime match {
      case None => false
      case Some(sch) => sch.millisSinceEpoch > thresholdMillis
    }
  }

  def twoDaysAgo: MillisSinceEpoch = {
    SDate.now().millisSinceEpoch - (2 * oneDayMillis)
  }
}
