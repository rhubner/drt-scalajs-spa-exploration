package services.crunch

import akka.actor.ActorRef
import akka.stream.OverflowStrategy
import akka.stream.scaladsl.Source
import akka.testkit.TestProbe
import controllers.ArrivalGenerator
import drt.shared.Crunch.CrunchState
import drt.shared.FlightsApi.Flights
import drt.shared.PaxTypes._
import drt.shared.PaxTypesAndQueues._
import drt.shared.Queues._
import drt.shared.SplitRatiosNs.SplitSources._
import drt.shared._
import services.SDate

import scala.collection.immutable.Seq


class FlightUpdatesTriggerNewCrunchStateSpec extends CrunchTestLike {
  isolated
  sequential

  "Given an update to an existing flight " +
    "When I expect a CrunchState " +
    "Then I should see one containing the updated flight" >> {

    val scheduled = "2017-01-01T00:00Z"

    val flight = ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduled, iata = "BA0001", terminal = "T1", actPax = 21)
    val inputFlightsBefore = Flights(List(flight))
    val updatedArrival = flight.copy(ActPax = 50)
    val inputFlightsAfter = Flights(List(updatedArrival))

    val flightsSource = Source.actorRef(1, OverflowStrategy.dropBuffer)
    val manifestsSource = Source.actorRef(1, OverflowStrategy.dropBuffer)
    val testProbe = TestProbe()
    val runnableGraphDispatcher =
      runCrunchGraph[ActorRef, ActorRef](
        procTimes = Map(
          eeaMachineReadableToDesk -> 25d / 60,
          eeaMachineReadableToEGate -> 25d / 60
        ),
        queues = Map("T1" -> Seq(EeaDesk, EGate)),
        testProbe = testProbe,
        crunchStartDateProvider = () => SDate(scheduled).millisSinceEpoch
      ) _

    val (fs, ms, _) = runnableGraphDispatcher(flightsSource, manifestsSource)

    fs ! inputFlightsBefore

    testProbe.expectMsgAnyClassOf(classOf[CrunchState])

    fs ! inputFlightsAfter

    val flightsAfterUpdate = testProbe.expectMsgAnyClassOf(classOf[CrunchState]) match {
      case CrunchState(_, _, flights, _) => flights.map(_.copy(lastUpdated = None))
    }

    val expectedFlights = Set(ApiFlightWithSplits(
      updatedArrival,
      Set(ApiSplits(Set(ApiPaxTypeAndQueueCount(EeaMachineReadable, Queues.EeaDesk, 100.0)), TerminalAverage, None, Percentage))))

    flightsAfterUpdate === expectedFlights
  }
}
