package services

import actors.{GetFlights, GetPortWorkload}
import akka.NotUsed
import akka.pattern.AskableActorRef
import akka.testkit.TestProbe
import akka.util.Timeout
import controllers.{ArrivalGenerator, GetTerminalCrunch}
import drt.shared.FlightsApi.{Flights, FlightsWithSplits, QueueName, TerminalName}
import drt.shared.PaxTypes.EeaMachineReadable
import drt.shared.PaxTypesAndQueues.eeaMachineReadableToDesk
import drt.shared.SplitRatiosNs.SplitSources
import drt.shared._
import org.joda.time.DateTimeZone
import passengersplits.parsing.VoyageManifestParser.VoyageManifest
import services.Crunch.{CrunchRequest, CrunchState}

import scala.collection.immutable.List
import scala.concurrent.Await
import scala.concurrent.duration._

class CrunchWindowRelevantDataSpec extends CrunchTestLike {
  isolated
  sequential

  "Relevant crunch state data for crunch window " >> {
    "Given two flights one reaching PCP before the crunch start time and one after " +
      "When I crunch and ask for flights " +
      "I should see only see the flight reaching PCP after the crunch start time " >> {
      val scheduledBeforeCrunchStart = "2017-01-01T00:00Z"
      val scheduledAtCrunchStart = "2017-01-02T00:00Z"

      val flights = List(Flights(List(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledBeforeCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20),
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20)
      )))

      val fiveMinutes = 600d / 60
      val procTimes: Map[PaxTypeAndQueue, Double] = Map(eeaMachineReadableToDesk -> fiveMinutes)

      val testProbe = TestProbe()
      val runnableGraphDispatcher: (List[Flights], List[Set[VoyageManifest]]) => AskableActorRef =
        runCrunchGraph(
          procTimes = procTimes,
          testProbe = testProbe,
          crunchStartDateProvider = () => SDate(scheduledAtCrunchStart).millisSinceEpoch,
          minMaxDesks = minMaxDesks,
          minutesToCrunch = 120
        )

      val askableCrunchStateTestActor = runnableGraphDispatcher(flights, Nil)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])


      val result = Await.result(askableCrunchStateTestActor.ask(GetFlights)(new Timeout(1 second)), 1 second).asInstanceOf[FlightsWithSplits]


      result.flights === List(ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20))
    }

    "Given two flights one reaching PCP before the crunch start time and one after " +
      "When I crunch and ask for workloads " +
      "I should see only see minutes falling within the crunch window " >> {
      val scheduledBeforeCrunchStart = "2017-01-01T00:00Z"
      val scheduledAtCrunchStart = "2017-01-02T00:00Z"

      val flights = List(Flights(List(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledBeforeCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20),
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20)
      )))

      val fiveMinutes = 600d / 60
      val procTimes: Map[PaxTypeAndQueue, Double] = Map(eeaMachineReadableToDesk -> fiveMinutes)

      val testProbe = TestProbe()
      val runnableGraphDispatcher: (List[Flights], List[Set[VoyageManifest]]) => AskableActorRef =
        runCrunchGraph(
          procTimes = procTimes,
          testProbe = testProbe,
          crunchStartDateProvider = () => SDate(scheduledAtCrunchStart).millisSinceEpoch,
          minMaxDesks = minMaxDesks,
          minutesToCrunch = 120
        )
      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch
      val endTime = startTime + (1440 * oneMinute)

      val askableCrunchStateTestActor = runnableGraphDispatcher(flights, Nil)
      val result = Await.result(askableCrunchStateTestActor.ask(GetPortWorkload)(new Timeout(1 second)), 1 second)
        .asInstanceOf[Map[TerminalName, Map[QueueName, (List[WL], List[Pax])]]]

      val wl = result("T1")(Queues.EeaDesk)._1

      val expectedLength = 1440
      val expectedWl = startTime until endTime by oneMinute

      (wl.length, wl.map(_.time).toSet) === (expectedLength, expectedWl.toSet)
    }

    "Given two flights one reaching PCP after the crunch window and one during " +
      "When I crunch and ask for workloads " +
      "I should see only see minutes falling within the crunch window " >> {
      val scheduledAfterCrunchEnd = "2017-01-03T00:00Z"
      val scheduledAtCrunchStart = "2017-01-02T00:00Z"

      val flights = List(Flights(List(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledAfterCrunchEnd, iata = "BA0001", terminal = "T1", actPax = 20),
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20)
      )))

      val fiveMinutes = 600d / 60
      val procTimes: Map[PaxTypeAndQueue, Double] = Map(eeaMachineReadableToDesk -> fiveMinutes)

      val testProbe = TestProbe()
      val runnableGraphDispatcher: (List[Flights], List[Set[VoyageManifest]]) => AskableActorRef =
        runCrunchGraph(
          procTimes = procTimes,
          testProbe = testProbe,
          crunchStartDateProvider = () => SDate(scheduledAtCrunchStart).millisSinceEpoch,
          minMaxDesks = minMaxDesks,
          minutesToCrunch = 120
        )
      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch
      val endTime = startTime + (1440 * oneMinute)

      val askableCrunchStateTestActor = runnableGraphDispatcher(flights, Nil)
      val result = Await.result(askableCrunchStateTestActor.ask(GetPortWorkload)(new Timeout(1 second)), 1 second)
        .asInstanceOf[Map[TerminalName, Map[QueueName, (List[WL], List[Pax])]]]

      val wl = result("T1")(Queues.EeaDesk)._1

      val expectedLength = 1440
      val expectedWl = startTime until endTime by oneMinute

      (wl.length, wl.map(_.time).toSet) === (expectedLength, expectedWl.toSet)
    }

    "Given two flights one reaching PCP before the crunch start time and one after " +
      "When I crunch and ask for crunch results " +
      "I should see only see minutes falling within the crunch window " >> {
      val scheduledBeforeCrunchStart = "2017-01-01T00:00Z"
      val scheduledAtCrunchStart = "2017-01-02T00:00Z"

      val flights = List(Flights(List(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledBeforeCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20),
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, iata = "BA0001", terminal = "T1", actPax = 20)
      )))

      val fiveMinutes = 600d / 60
      val procTimes: Map[PaxTypeAndQueue, Double] = Map(eeaMachineReadableToDesk -> fiveMinutes)

      val testProbe = TestProbe()
      val runnableGraphDispatcher: (List[Flights], List[Set[VoyageManifest]]) => AskableActorRef =
        runCrunchGraph(
          procTimes = procTimes,
          testProbe = testProbe,
          crunchStartDateProvider = () => SDate(scheduledAtCrunchStart).millisSinceEpoch,
          minMaxDesks = minMaxDesks,
          minutesToCrunch = 120
        )
      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch
      val endTime = startTime + (1440 * oneMinute)

      val askableCrunchStateTestActor = runnableGraphDispatcher(flights, Nil)

      val result = Await
        .result(askableCrunchStateTestActor.ask(GetTerminalCrunch("T1"))(new Timeout(1 second)), 1 second)
        .asInstanceOf[List[(QueueName, Right[NoCrunchAvailable, CrunchResult])]]

      val deskRecMinutes = result.head._2.b.recommendedDesks.length

      val expected = 1440

      deskRecMinutes === expected
    }
  }
}
