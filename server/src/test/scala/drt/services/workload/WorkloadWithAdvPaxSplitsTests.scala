package drt.services.workload

import akka.actor.{Actor, ActorSystem, Props}
import akka.pattern.AskableActorRef
import akka.testkit.TestKit
import akka.util.Timeout
import com.typesafe.config.ConfigFactory
import drt.services.workload.SplitsMocks.{MockSplitsActor, NotFoundSplitsActor}
import org.specs2.mutable.SpecificationLike
import passengersplits.core.PassengerInfoRouterActor.ReportVoyagePaxSplit
import services.SDate.implicits._
import services.workloadcalculator.PaxLoadCalculator
import services.{SDate, WorkloadCalculatorTests}
import drt.shared.PassengerSplits.{FlightNotFound, PaxTypeAndQueueCount, VoyagePaxSplits}
import drt.shared.PaxTypes.EeaMachineReadable
import drt.shared.SplitRatiosNs.{SplitRatio, SplitRatios}
import drt.shared._
import drt.shared.Queues._

import scala.concurrent.{Await, ExecutionContext}
import scala.concurrent.duration._

object AdvPaxSplitsProvider {
  def splitRatioProvider(passengerInfoRouterActor: AskableActorRef)
                        (flight: ApiFlight)
                        (implicit timeOut: Timeout, ec: ExecutionContext): Option[SplitRatios] = {
    FlightParsing.parseIataToCarrierCodeVoyageNumber(flight.IATA) match {
      case Some((cc, number)) =>
        val futResp = passengerInfoRouterActor ? ReportVoyagePaxSplit(flight.Origin, cc, number, SDate.parseString(flight.SchDT))
        val splitsFut = futResp.map {
          case voyagePaxSplits: VoyagePaxSplits =>
            Some(convertVoyagePaxSplitPeopleCountsToSplitRatios(voyagePaxSplits))
          case fnf: FlightNotFound =>
            None
        }
        Await.result(splitsFut, 1 second)
    }
  }

  def convertVoyagePaxSplitPeopleCountsToSplitRatios(splits: VoyagePaxSplits) = {
    SplitRatios(splits.paxSplits
      .map(split => SplitRatio(
        PaxTypeAndQueue(split), split.paxCount.toDouble / splits.totalPaxCount)))
  }

}

object SplitsMocks {

  class MockSplitsActor extends Actor {
    def receive: Receive = {
      case ReportVoyagePaxSplit(dp, carrierCode, voyageNumber, scheduledArrivalDateTime) =>
        val splits: VoyagePaxSplits = testVoyagePaxSplits(scheduledArrivalDateTime, List(
          PaxTypeAndQueueCount(EeaMachineReadable, EeaDesk, 10),
          PaxTypeAndQueueCount(EeaMachineReadable, EGate, 10)
        ))
        sender ! splits
    }
  }

  class NotFoundSplitsActor extends Actor {
    def receive: Receive = {
      case ReportVoyagePaxSplit(dp, carrierCode, voyageNumber, scheduledArrivalDateTime) =>
        sender ! FlightNotFound(carrierCode, voyageNumber, scheduledArrivalDateTime)
    }
  }

  def testVoyagePaxSplits(scheduledArrivalDateTime: SDateLike, passengerNumbers: List[PaxTypeAndQueueCount]) = {
    val splits = VoyagePaxSplits("LGW", "BA", "0001", passengerNumbers.map(_.paxCount).sum, scheduledArrivalDateTime, passengerNumbers)
    splits
  }
}


class WorkloadWithAdvPaxSplitsTests extends TestKit(ActorSystem("WorkloadwithAdvPaxInfoSplits", ConfigFactory.empty())) with SpecificationLike {
  isolated

  implicit val timeout: Timeout = 3 seconds

  import WorkloadCalculatorTests._

  import scala.concurrent.ExecutionContext.Implicits.global

  import AdvPaxSplitsProvider._

  "voyagePaxSplitsAsPaxLoadPaxTypeAndQueueCount " >> {
    "VoyagePaxSplits can  be converted to a SplitRatios as used by the extant PaxLoadCalculator" >> {
      val splits = SplitsMocks.testVoyagePaxSplits(SDate(2017, 1, 1, 12, 20), List(
        PaxTypeAndQueueCount(EeaMachineReadable, EeaDesk, 10),
        PaxTypeAndQueueCount(EeaMachineReadable, EGate, 10)
      ))
      convertVoyagePaxSplitPeopleCountsToSplitRatios(splits) ===
        SplitRatios(
          SplitRatio(
            PaxTypeAndQueue(EeaMachineReadable, EeaDesk), 0.5),
          SplitRatio(
            PaxTypeAndQueue(EeaMachineReadable, EGate), 0.5))
    }


    "VoyagePaxSplits can  be converted to a SplitRatios as used by the extant PaxLoadCalculator 2/8 => 0.2:0.8" >> {
      val splits = SplitsMocks.testVoyagePaxSplits(SDate(2017, 1, 1, 12, 20), List(
        PaxTypeAndQueueCount(EeaMachineReadable, EeaDesk, 2),
        PaxTypeAndQueueCount(EeaMachineReadable, EGate, 8)
      ))
      convertVoyagePaxSplitPeopleCountsToSplitRatios(splits) ===
        SplitRatios(
          SplitRatio(
            PaxTypeAndQueue(EeaMachineReadable, EeaDesk), 0.2),
          SplitRatio(
            PaxTypeAndQueue(EeaMachineReadable, EGate), 0.8))
    }
    "VoyagePaxSplits can  be converted to a SplitRatios as used by the extant PaxLoadCalculator" >> {
      val splits = SplitsMocks.testVoyagePaxSplits(SDate(2017, 1, 1, 12, 20), Nil)
      convertVoyagePaxSplitPeopleCountsToSplitRatios(splits) === SplitRatios()
    }
  }


  "WorkloadCalculator with AdvancePassengerInfoSplitProvider" >> {
    """Given AdvancePassengerInfo paxSplits for a flight
      |When we calculate paxload then it uses the splits from the actor
    """.stripMargin in {
      implicit def tupleToPaxTypeAndQueueCounty(t: (PaxType, String)): PaxTypeAndQueue = PaxTypeAndQueue(t._1, t._2)

      "queueWorkloadCalculator" in {
        "given the flight can be found " >> {
          def defaultProcTimesProvider(paxTypeAndQueue: PaxTypeAndQueue) = 1

          "with simple pax splits all at the same paxType" in {
            val passengerInfoRouterActor: AskableActorRef = system.actorOf(Props(classOf[MockSplitsActor]))

            val provider = splitRatioProvider(passengerInfoRouterActor) _
            val calcPaxTypeAndQueueCountForAFlightOverTime = PaxLoadCalculator.voyagePaxSplitsFlowOverTime(provider) _

            val sut = PaxLoadCalculator.queueWorkAndPaxLoadCalculator(calcPaxTypeAndQueueCountForAFlightOverTime, defaultProcTimesProvider) _

            "Workload calculator should" in {

              "Given a single flight with one minute's worth of flow when we apply paxSplits and flow rate, then we should see flow applied to the flight, and splits applied to that flow" in {
                val startTime: String = "2020-01-01T00:00:00Z"
                val flights = List(apiFlight("BA0001", "LHR", 20, startTime))

                val workloads = extractWorkloads(sut(flights)).toSet
                val expected = Map(
                  Queues.EGate -> List(WL(asMillis("2020-01-01T00:00:00Z"), 10.0)),
                  Queues.EeaDesk -> List(WL(asMillis("2020-01-01T00:00:00Z"), 10.0))).toSet
                workloads === expected
              }


            }
          }
        }

        "given the flight cannot be found" >> {
          "with simple pax splits all at the same paxType" in {
            val passengerInfoRouterActor: AskableActorRef = system.actorOf(Props(classOf[NotFoundSplitsActor]))
            "If the flight isn't found in the AdvPaxInfo actor splitRatioProvider should return None" in {
              val startTime: String = "2020-01-01T00:00:00Z"

              splitRatioProvider(passengerInfoRouterActor)(apiFlight("ZZ9999", "LHR", 20, startTime)) === None
            }
          }
        }
      }
    }
  }
}
