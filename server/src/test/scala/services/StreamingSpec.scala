package services

import actors.TimeZone
import actors.TimeZone.localTimeZone
import akka.NotUsed
import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import akka.stream.scaladsl._
import controllers.ArrivalGenerator
import drt.shared.FlightsApi.QueueName
import drt.shared.PaxTypesAndQueues._
import drt.shared._
import org.joda.time.{DateTime, DateTimeZone, LocalDate}
import org.joda.time.format.DateTimeFormat
import org.specs2.mutable.Specification
import services.workloadcalculator.PaxLoadCalculator._

import scala.collection.immutable
import scala.concurrent.{Await, Future}
import scala.concurrent.duration._

case class FlightSplitMinute(flightId: Int, paxType: PaxType, queueName: QueueName, paxLoad: Double, workLoad: Double, minute: Long)

case class QueueLoadMinute(queueName: QueueName, paxLoad: Double, workLoad: Double, minute: Long)

case class QueueMinute(queueName: QueueName, paxLoad: Double, workLoad: Double, crunchDesks: Int, crunchWait: Int, allocStaff: Int, allocWait: Int, minute: Long)

class StreamingSpec extends Specification {
  implicit val system = ActorSystem("reactive-crunch")
  implicit val materializer = ActorMaterializer()

  "Given a flight with one passenger and one split to eea desk " +
    "When I ask for queue loads " +
    "Then I should see a single eea desk queue load containing the passenger and their proc time" >> {
    val scheduled = "2017-01-01T00:00Z"
    val flightsWithSplits = List(ApiFlightWithSplits(
      ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduled),
      List(ApiSplits(
        List(ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 1d)), "api", PaxNumbers))))
    val emr2dProcTime = 20d / 60
    val emr2eProcTime = 35d / 60
    val procTimes: Map[PaxTypeAndQueue, Double] = Map(
      eeaMachineReadableToDesk -> emr2dProcTime,
      eeaMachineReadableToEGate -> emr2eProcTime
    )
    val flightsWithSplitsSets = Source(List(flightsWithSplits))

    val queueLoads = flightsToQueueLoadMinutes(flightsWithSplitsSets, procTimes)
    val result = Await.result(queueLoads.runWith(Sink.seq), 1 second)

    val expected = Vector(List(QueueLoadMinute(Queues.EeaDesk, 1.0, emr2dProcTime, SDate(scheduled, DateTimeZone.UTC).millisSinceEpoch)))

    result === expected
  }

  "Given a flight with one passenger and splits to eea desk & egates " +
    "When I ask for queue loads " +
    "Then I should see 2 queue loads, each representing their portion of the passenger and the split queue" >> {
    val scheduled = "2017-01-01T00:00Z"
    val scheduledMillis = SDate(scheduled, DateTimeZone.UTC).millisSinceEpoch
    val edPax = 0.25
    val egPax = 0.75
    val flightsWithSplits = List(ApiFlightWithSplits(
      ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduled),
      List(ApiSplits(List(
        ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, edPax),
        ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EGate, egPax)
      ), "api", PaxNumbers))))
    val emr2dProcTime = 20d / 60
    val emr2eProcTime = 35d / 60
    val procTimes: Map[PaxTypeAndQueue, Double] = Map(
      eeaMachineReadableToDesk -> emr2dProcTime,
      eeaMachineReadableToEGate -> emr2eProcTime
    )

    val flightsWithSplitsSets = Source(List(flightsWithSplits))
    val queueLoads = flightsToQueueLoadMinutes(flightsWithSplitsSets, procTimes)

    val result = Await.result(queueLoads.runWith(Sink.seq), 1 second) match {
      case Vector(queueLoadMinutes) => queueLoadMinutes.toSet
    }
    val expected = Set(
      QueueLoadMinute(Queues.EeaDesk, edPax, edPax * emr2dProcTime, scheduledMillis),
      QueueLoadMinute(Queues.EGate, egPax, egPax * emr2eProcTime, scheduledMillis))

    result === expected
  }

  "Given a flight with 21 passengers and splits to eea desk & egates " +
    "When I ask for queue loads " +
    "Then I should see 4 queue loads, 2 for the first 20 pax to each queue and 2 for the last 1 split to each queue" >> {
    val scheduled = "2017-01-01T00:00Z"
    val scheduledMillis = SDate(scheduled, DateTimeZone.UTC).millisSinceEpoch
    val totalPax = 21
    val edSplit = 0.25
    val egSplit = 0.75
    val edPax = edSplit * totalPax
    val egPax = egSplit * totalPax
    val flightsWithSplits = List(ApiFlightWithSplits(
      ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduled),
      List(ApiSplits(List(
        ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, edPax),
        ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EGate, egPax)
      ), "api", PaxNumbers))))
    val emr2dProcTime = 20d / 60
    val emr2eProcTime = 35d / 60
    val procTimes: Map[PaxTypeAndQueue, Double] = Map(
      eeaMachineReadableToDesk -> emr2dProcTime,
      eeaMachineReadableToEGate -> emr2eProcTime
    )

    val flightsWithSplitsSets = Source(List(flightsWithSplits))

    val queueLoads = flightsToQueueLoadMinutes(flightsWithSplitsSets, procTimes)

    val result = Await.result(queueLoads.runWith(Sink.seq), 1 second) match {
      case Vector(queueLoadMinutes) => queueLoadMinutes.toSet
    }
    val expected = Set(
      QueueLoadMinute(Queues.EeaDesk, 20 * edSplit, 20 * edSplit * emr2dProcTime, scheduledMillis),
      QueueLoadMinute(Queues.EGate, 20 * egSplit, 20 * egSplit * emr2eProcTime, scheduledMillis),
      QueueLoadMinute(Queues.EeaDesk, 1 * edSplit, 1 * edSplit * emr2dProcTime, scheduledMillis + 60000),
      QueueLoadMinute(Queues.EGate, 1 * egSplit, 1 * egSplit * emr2eProcTime, scheduledMillis + 60000))

    result === expected
  }

  "Given 2 flights with one passenger each and one split to eea desk arriving at pcp 1 minute apart" +
    "When I ask for queue loads " +
    "Then I should see two eea desk queue loads containing the 2 passengers and their proc time" >> {
    val scheduled1 = "2017-01-01T00:00Z"
    val scheduled2 = "2017-01-01T00:01Z"
    val flightsWithSplits = List(ApiFlightWithSplits(
      ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduled1),
      List(ApiSplits(
        List(ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 1d)), "api", PaxNumbers))
    ), ApiFlightWithSplits(
      ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduled2),
      List(ApiSplits(
        List(ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 1d)), "api", PaxNumbers))
    ))
    val emr2dProcTime = 20d / 60
    val emr2eProcTime = 35d / 60
    val procTimes: Map[PaxTypeAndQueue, Double] = Map(
      eeaMachineReadableToDesk -> emr2dProcTime,
      eeaMachineReadableToEGate -> emr2eProcTime
    )
    val flightsWithSplitsSets = Source(List(flightsWithSplits))

    val queueLoads = flightsToQueueLoadMinutes(flightsWithSplitsSets, procTimes)

    val result = Await.result(queueLoads.runWith(Sink.seq), 1 second) match {
      case Vector(queueLoadMinutes) => queueLoadMinutes.toSet
    }
    val expected = Set(
      QueueLoadMinute(Queues.EeaDesk, 1.0, emr2dProcTime, SDate(scheduled1, DateTimeZone.UTC).millisSinceEpoch),
      QueueLoadMinute(Queues.EeaDesk, 1.0, emr2dProcTime, SDate(scheduled1, DateTimeZone.UTC).millisSinceEpoch + 60000))

    result === expected
  }

  "Given one queue load minute " +
    "When I ask for a crunch result " +
    "Then I should get appropriate desk recs" >> {
    val scheduled = "2017-01-01T00:00Z"
    val queueLoadSets = Source(List(Set(
      QueueLoadMinute(Queues.EeaDesk, 1.0, 0.25, SDate(scheduled, DateTimeZone.UTC).millisSinceEpoch)
    )))
    val workloadFor24Hours = queueLoadSets.map {
      case queueLoads =>
        val now = new DateTime(SDate(scheduled).millisSinceEpoch)
        val start = now.toLocalDate.toDateTimeAtStartOfDay(DateTimeZone.forID("Europe/London")).getMillis
        val minutes = List.range(start, start + (1000 * 60 * 60 * 24))
    }
  }



  def lastLocalMidnightString(millis: Long): String = {
    val formatter = DateTimeFormat.forPattern("yyyy-MM-dd")
    // todo this function needs more work to make it a sensible cut off time
    lastLocalMidnight(new DateTime(millis)).toString(formatter)
  }

  def lastLocalMidnight(pointInTime: DateTime): DateTime = {
    TimeZone.lastLocalMidnightOn(pointInTime)
  }

  private def flightsToFlightSplitMinutes(flightsWithSplitsSource: Source[List[ApiFlightWithSplits], NotUsed], procTimes: Map[PaxTypeAndQueue, Double]) = {
    flightsWithSplitsSource.map {
      case flightsWithSplits =>
        flightsWithSplits.flatMap {
          case ApiFlightWithSplits(flight, splits) =>
            val flightSplitMinutes: immutable.Seq[FlightSplitMinute] = flightToFlightSplitMinutes(flight, splits, procTimes)

            flightSplitMinutes
        }
    }
  }

  private def flightsToQueueLoadMinutes(flightsWithSplitsSource: Source[List[ApiFlightWithSplits], NotUsed], procTimes: Map[PaxTypeAndQueue, Double]) = {
    flightsWithSplitsSource.map {
      case flightsWithSplits =>
        flightsWithSplits.flatMap {
          case ApiFlightWithSplits(flight, splits) =>
            val flightSplitMinutes: immutable.Seq[FlightSplitMinute] = flightToFlightSplitMinutes(flight, splits, procTimes)
            val queueLoadMinutes: immutable.Iterable[QueueLoadMinute] = flightSplitMinutesToQueueLoadMinutes(flightSplitMinutes)

            queueLoadMinutes
        }
    }
  }

  private def flightToFlightSplitMinutes(flight: Arrival, splits: List[ApiSplits], procTimes: Map[PaxTypeAndQueue, Double]) = {
    val splitsToUse = splits.head
    val totalPax = splitsToUse.splits.map(qc => qc.paxCount).sum
    val splitRatios = splitsToUse.splits.map(qc => qc.copy(paxCount = qc.paxCount / totalPax))

    minutesForHours(flight.PcpTime, 1)
      .zip(paxDeparturesPerMinutes(totalPax.toInt, paxOffFlowRate))
      .flatMap {
        case (minuteMillis, flightPaxInMinute) =>
          splitRatios.map(apiSplitRatio => flightSplitMinute(flight, procTimes, minuteMillis, flightPaxInMinute, apiSplitRatio))
      }
  }

  private def flightSplitMinute(flight: Arrival, procTimes: Map[PaxTypeAndQueue, Load], minuteMillis: MillisSinceEpoch, flightPaxInMinute: Int, apiSplitRatio: ApiPaxTypeAndQueueCount) = {
    val splitPaxInMinute = apiSplitRatio.paxCount * flightPaxInMinute
    val splitWorkLoadInMinute = splitPaxInMinute * procTimes(PaxTypeAndQueue(apiSplitRatio.passengerType, apiSplitRatio.queueType))
    FlightSplitMinute(flight.FlightID, apiSplitRatio.passengerType, apiSplitRatio.queueType, splitPaxInMinute, splitWorkLoadInMinute, minuteMillis)
  }

  private def flightSplitMinutesToQueueLoadMinutes(flightSplitMinutes: immutable.Seq[FlightSplitMinute]) = {
    flightSplitMinutes
      .groupBy(s => (s.queueName, s.minute)).map {
      case ((queueName, minute), fsms) =>
        val paxLoad = fsms.map(_.paxLoad).sum
        val workLoad = fsms.map(_.workLoad).sum
        QueueLoadMinute(queueName, paxLoad, workLoad, minute)
    }
  }
}
