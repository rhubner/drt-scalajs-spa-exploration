package services

import actors.{GetFlights, GetPortWorkload}
import akka.pattern.AskableActorRef
import akka.testkit.TestProbe
import akka.util.Timeout
import controllers.{ArrivalGenerator, GetTerminalCrunch}
import drt.shared.FlightsApi.{FlightsWithSplits, QueueName, TerminalName}
import drt.shared.PaxTypes.EeaMachineReadable
import drt.shared.SplitRatiosNs.SplitSources
import drt.shared._
import org.joda.time.DateTimeZone
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

      val flightOutsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledBeforeCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))
      val flightInsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))

      val flightsWithSplits = List(flightOutsideCrunchWindow, flightInsideCrunchWindow)

      val testProbe = TestProbe()
      val (subscriber, crunchStateTestActor) = flightsSubscriberAndCrunchStateTestActor(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch

      initialiseAndSendFlights(flightsWithSplits, subscriber, startTime, numberOfMinutes = 30)
      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      val askableCrunchStateTestActor: AskableActorRef = crunchStateTestActor
      val result = Await.result(askableCrunchStateTestActor.ask(GetFlights)(new Timeout(1 second)), 1 second).asInstanceOf[FlightsWithSplits]

      val expected = FlightsWithSplits(List(flightInsideCrunchWindow))

      result === expected
    }

    "Given two flights one reaching PCP before the crunch start time and one after " +
      "When I crunch and ask for workloads " +
      "I should see only see minutes falling within the crunch window " >> {
      val scheduledBeforeCrunchStart = "2017-01-01T00:00Z"
      val scheduledAtCrunchStart = "2017-01-02T00:00Z"

      val flightOutsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledBeforeCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))
      val flightInsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))

      val flightsWithSplits = List(flightOutsideCrunchWindow, flightInsideCrunchWindow)

      val testProbe = TestProbe()
      val (subscriber, crunchStateTestActor) = flightsSubscriberAndCrunchStateTestActor(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch
      val endTime = startTime + (1440 * oneMinute)

      initialiseAndSendFlights(flightsWithSplits, subscriber, startTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      val askableCrunchStateTestActor: AskableActorRef = crunchStateTestActor
      val result = Await
        .result(askableCrunchStateTestActor.ask(GetPortWorkload)(new Timeout(1 second)), 1 second)
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

      val flightOutsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledAfterCrunchEnd, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))
      val flightInsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))

      val flightsWithSplits = List(flightOutsideCrunchWindow, flightInsideCrunchWindow)

      val testProbe = TestProbe()
      val (subscriber, crunchStateTestActor) = flightsSubscriberAndCrunchStateTestActor(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch
      val endTime = startTime + (1440 * oneMinute)

      initialiseAndSendFlights(flightsWithSplits, subscriber, startTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      val askableCrunchStateTestActor: AskableActorRef = crunchStateTestActor
      val result = Await
        .result(askableCrunchStateTestActor.ask(GetPortWorkload)(new Timeout(1 second)), 1 second)
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

      val flightOutsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledBeforeCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))
      val flightInsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))

      val flightsWithSplits = List(flightOutsideCrunchWindow, flightInsideCrunchWindow)

      val testProbe = TestProbe()
      val (subscriber, crunchStateTestActor) = flightsSubscriberAndCrunchStateTestActor(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch

      initialiseAndSendFlights(flightsWithSplits, subscriber, startTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      val askableCrunchStateTestActor: AskableActorRef = crunchStateTestActor
      val result = Await
        .result(askableCrunchStateTestActor.ask(GetTerminalCrunch("T1"))(new Timeout(1 second)), 1 second)
        .asInstanceOf[List[(QueueName, Right[NoCrunchAvailable, CrunchResult])]]

      val deskRecMinutes = result.head._2.b.recommendedDesks.length

      val expected = 1440

      deskRecMinutes === expected
    }

    "Given two flights one reaching PCP after the crunch window and one during " +
      "When I crunch and ask for crunch results " +
      "I should see only see minutes falling within the crunch window " >> {
      val scheduledAfterCrunchEnd = "2017-01-03T00:00Z"
      val scheduledAtCrunchStart = "2017-01-02T00:00Z"

      val flightOutsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledAfterCrunchEnd, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))
      val flightInsideCrunchWindow = ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledAtCrunchStart, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage)))

      val flightsWithSplits = List(flightOutsideCrunchWindow, flightInsideCrunchWindow)

      val testProbe = TestProbe()
      val (subscriber, crunchStateTestActor) = flightsSubscriberAndCrunchStateTestActor(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val startTime = SDate(scheduledAtCrunchStart, DateTimeZone.UTC).millisSinceEpoch

      initialiseAndSendFlights(flightsWithSplits, subscriber, startTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      val askableCrunchStateTestActor: AskableActorRef = crunchStateTestActor
      val result = Await
        .result(askableCrunchStateTestActor.ask(GetTerminalCrunch("T1"))(new Timeout(1 second)), 1 second)
        .asInstanceOf[List[(QueueName, Right[NoCrunchAvailable, CrunchResult])]]

      val deskRecMinutes = result.head._2.b.recommendedDesks.length

      val expected = 1440

      deskRecMinutes === expected
    }

    "Given an empty crunch state " +
      "When I first crunch one date and then crunch the day after " +
      "Then I should see a full set of exactly 1440 load minutes" >> {

      val scheduledFirstDate = "2017-01-01T00:00Z"
      val scheduledNextDay = "2017-01-02T00:00Z"

      val flightsForFirstDayCrunch = List(ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledFirstDate, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage))))

      val flightsForNextDayCrunch = List(ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledNextDay, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage))))

      val testProbe = TestProbe()
      val (subscriber, crunchStateTestActor) = flightsSubscriberAndCrunchStateTestActor(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val firstDayCrunchStartTime = SDate(scheduledFirstDate, DateTimeZone.UTC).millisSinceEpoch
      val nextDayCrunchStartTime = SDate(scheduledFirstDate, DateTimeZone.UTC).millisSinceEpoch

      initialiseAndSendFlights(flightsForFirstDayCrunch, subscriber, firstDayCrunchStartTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      subscriber ! CrunchRequest(flightsForNextDayCrunch, nextDayCrunchStartTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      val askableCrunchStateTestActor: AskableActorRef = crunchStateTestActor
      val result = Await
        .result(askableCrunchStateTestActor.ask(GetPortWorkload)(new Timeout(1 second)), 1 second)
        .asInstanceOf[Map[TerminalName, Map[QueueName, (List[WL], List[Pax])]]]

      val wl = result("T1")(Queues.EeaDesk)._1

      val expectedLength = 1440
      val expectedWl = nextDayCrunchStartTime until (nextDayCrunchStartTime + (1440 * oneMinute)) by oneMinute

      (wl.length, wl.map(_.time).toSet) === (expectedLength, expectedWl.toSet)
    }

    "Given an empty crunch state " +
      "When I first crunch one date and then crunch the day after " +
      "Then I should see a full set of exactly 1440 desk rec minutes" >> {

      val scheduledFirstDate = "2017-01-01T00:00Z"
      val scheduledNextDay = "2017-01-02T00:00Z"

      val flightsForFirstDayCrunch = List(ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledFirstDate, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage))))

      val flightsForNextDayCrunch = List(ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledNextDay, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage))))

      val testProbe = TestProbe()
      val (subscriber, crunchStateTestActor) = flightsSubscriberAndCrunchStateTestActor(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val firstDayCrunchStartTime = SDate(scheduledFirstDate, DateTimeZone.UTC).millisSinceEpoch
      val nextDayCrunchStartTime = SDate(scheduledNextDay, DateTimeZone.UTC).millisSinceEpoch

      initialiseAndSendFlights(flightsForFirstDayCrunch, subscriber, firstDayCrunchStartTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      subscriber ! CrunchRequest(flightsForNextDayCrunch, nextDayCrunchStartTime, numberOfMinutes = 1440)

      testProbe.expectMsgAnyClassOf(classOf[CrunchState])

      val askableCrunchStateTestActor: AskableActorRef = crunchStateTestActor
      val result = Await
        .result(askableCrunchStateTestActor.ask(GetTerminalCrunch("T1"))(new Timeout(1 second)), 1 second)
        .asInstanceOf[List[(QueueName, Right[NoCrunchAvailable, CrunchResult])]]

      val deskRecMinutes = result.head._2.b.recommendedDesks.length

      val expected = 1440

      deskRecMinutes === expected
    }

    "Given an empty crunch state " +
      "When I first crunch one date and then crunch the day after " +
      "Then I should see a CrunchStates start times matching the crunch requests" >> {

      val scheduledFirstDate = "2017-01-01T00:00Z"
      val scheduledNextDay = "2017-01-02T00:00Z"

      val flightsForFirstDayCrunch = List(ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduledFirstDate, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage))))

      val flightsForNextDayCrunch = List(ApiFlightWithSplits(
        ArrivalGenerator.apiFlight(flightId = 2, schDt = scheduledNextDay, actPax = 20),
        List(ApiSplits(List(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 50)), SplitSources.Historical, Percentage))))

      val testProbe = TestProbe()
      val subscriber = flightsSubscriber(procTimes, slaByQueue, minMaxDesks, queues, testProbe, validTerminals)

      val firstDayCrunchStartTime = SDate(scheduledFirstDate, DateTimeZone.UTC).millisSinceEpoch
      val nextDayCrunchStartTime = SDate(scheduledNextDay, DateTimeZone.UTC).millisSinceEpoch

      initialiseAndSendFlights(flightsForFirstDayCrunch, subscriber, firstDayCrunchStartTime, numberOfMinutes = 1440)
      val cs1 = testProbe.expectMsgAnyClassOf(10 seconds, classOf[CrunchState])

      subscriber ! CrunchRequest(flightsForNextDayCrunch, nextDayCrunchStartTime, numberOfMinutes = 1440)
      val cs2 = testProbe.expectMsgAnyClassOf(10 seconds, classOf[CrunchState])

      cs1.crunchFirstMinuteMillis === firstDayCrunchStartTime && cs2.crunchFirstMinuteMillis === nextDayCrunchStartTime
    }
  }
}
