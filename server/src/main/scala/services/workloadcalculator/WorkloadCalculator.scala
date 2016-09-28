package services.workloadcalculator

import org.joda.time.{DateTime, DateTimeZone}
import org.slf4j.LoggerFactory
import services.workloadcalculator.PassengerQueueTypes.{PaxType, PaxTypeAndQueueCount}
import services.workloadcalculator.PaxLoadAt.PaxTypeAndQueue
import spatutorial.shared.FlightsApi.{QueueName, QueueWorkloads}
import spatutorial.shared.{ApiFlight, Pax, WL}

import scala.collection.immutable.{IndexedSeq, Nil}


object PaxLoadAt {
  case class PaxTypeAndQueue(passengerType: PaxType, queueType: String)
}

case class SplitRatio(paxType: PaxTypeAndQueue, ratio: Double)

object PaxLoadCalculator {
  val log = LoggerFactory.getLogger(getClass)
  val paxOffFlowRate = 20
  val oneMinute = 60000L

  def queueWorkloadCalculator(splitsRatioProvider: ApiFlight => List[SplitRatio])(flights: List[ApiFlight]): Map[QueueName, QueueWorkloads] = {
    val paxLoadsByDesk: Map[String, (List[WL], List[Pax])] = paxLoadsByQueue(splitsRatioProvider, flights)
    paxLoadsByDesk
  }

  def paxLoadsByQueue(splitsRatioProvider: (ApiFlight) => List[SplitRatio], flights: List[ApiFlight]): Map[String, (List[WL], List[Pax])] = {
    val something = voyagePaxSplitsFromApiFlight(splitsRatioProvider)_
    val voyagePaxSplits: List[(Long, PaxTypeAndQueueCount)] = flights.flatMap(something)
    val paxLoadsByDeskAndMinute: Map[(String, Long), List[(Long, PaxTypeAndQueueCount)]] = voyagePaxSplits.groupBy(t => (t._2.paxAndQueueType.queueType, t._1))
    val paxLoadsByDeskAndTime: Map[(String, Long), Double] = paxLoadsByDeskAndMinute.mapValues(_.map(_._2.paxCount).sum)
    val queueWithPaxloads: Map[String, (List[WL], List[Pax])] = paxLoadsByDeskAndTime.toSeq.map {
      case ((queueName, time), paxload) => (queueName, (WL(time, paxload), Pax(time, paxload)))
    }.groupBy(_._1).mapValues(tuples => (tuples.map(_._2._1).sortBy(_.time).toList, tuples.map(_._2._2).sortBy(_.time).toList))

    queueWithPaxloads
  }

  def voyagePaxSplitsFromApiFlight(splitsRatioProvider: (ApiFlight) => List[SplitRatio])(flight: ApiFlight): IndexedSeq[(Long, PaxTypeAndQueueCount)] = {
    val timesMin = new DateTime(flight.SchDT, DateTimeZone.UTC).getMillis
    val splits = splitsRatioProvider(flight)
    val splitsOverTime: IndexedSeq[(Long, PaxTypeAndQueueCount)] = minsForNextNHours(timesMin, 1)
      .zip(paxDeparturesPerMinutes(flight.ActPax, paxOffFlowRate))
      .flatMap {
        case (m, paxInMinute) =>
          splits.map(splitRatio => (m, PaxTypeAndQueueCount(splitRatio.paxType, splitRatio.ratio * paxInMinute)))
      }

    splitsOverTime
  }

  def minsForNextNHours(timesMin: Long, hours: Int) = timesMin until (timesMin + oneMinute * 60 * hours) by oneMinute

  def paxDeparturesPerMinutes(remainingPax: Int, departRate: Int): List[Int] = {
    if (remainingPax % departRate != 0)
      List.fill(remainingPax / departRate)(departRate) ::: remainingPax % departRate :: Nil
    else
      List.fill(remainingPax / departRate)(departRate)
  }
}

object PassengerQueueTypes {

  sealed trait PaxType {
    def name = getClass.getName
  }

  object Queues {
    val eeaDesk = "eeaDesk"
    val eGate = "eGate"
    val nonEeaDesk = "nonEeaDesk"
  }

  object PaxTypes {

    case object eeaNonMachineReadable extends PaxType

    case object visaNational extends PaxType

    case object eeaMachineReadable extends PaxType

    case object nonVisaNational extends PaxType

  }

  val eGatePercentage = 0.6

  type FlightCode = String

  case class VoyagePaxSplits(destinationPort: String, flightCode: FlightCode, scheduledArrivalDateTime: DateTime, paxSplits: List[(Int, PaxTypeAndQueueCount)])

  case class VoyagesPaxSplits(voyageSplits: List[VoyagePaxSplits])

  case class PaxTypeAndQueueCount(paxAndQueueType: PaxTypeAndQueue, paxCount: Double)

}

