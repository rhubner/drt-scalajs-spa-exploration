package services.crunch

import akka.NotUsed
import akka.stream.scaladsl.Source
import akka.testkit.TestProbe
import controllers.ArrivalGenerator
import drt.shared.Crunch.{MillisSinceEpoch, PortState}
import drt.shared.FlightsApi.Flights
import drt.shared.PaxTypesAndQueues.eeaMachineReadableToDesk
import drt.shared._
import org.joda.time.DateTimeZone
import services.SDate
import services.graphstages.Crunch._

import scala.collection.immutable.{List, Seq}
import scala.concurrent.duration._


class CrunchTimezoneSpec extends CrunchTestLike {
  "Crunch timezone " >> {
    "Given an SDateLike for a date outside BST" +
      "When I ask for a corresponding cunch start time " +
      "Then I should get an SDateLike representing the previous midnight UTC" >> {
      val now = SDate("2010-01-02T11:39", DateTimeZone.forID("Europe/London"))

      val result = getLocalLastMidnight(now).millisSinceEpoch
      val expected = SDate("2010-01-02T00:00").millisSinceEpoch

      result === expected
    }

    "Given an SDateLike for a date inside BST" +
      "When I ask for a corresponding cunch start time " +
      "Then I should get an SDateLike representing the previous midnight UTC" >> {
      val now = SDate("2010-07-02T11:39", DateTimeZone.forID("Europe/London"))
      val result: MillisSinceEpoch = getLocalLastMidnight(now).millisSinceEpoch
      val expected = SDate("2010-07-01T23:00").millisSinceEpoch

      result === expected
    }

    "Min / Max desks in BST " >> {
      "Given flights with one passenger and one split to eea desk " +
        "When the date falls within BST " +
        "Then I should see min desks allocated in alignment with BST" >> {
        val minMaxDesks = Map("T1" -> Map(Queues.EeaDesk -> Tuple2(0 :: 5 :: List.fill[Int](22)(0), List.fill[Int](24)(20))))

        val scheduled = "2017-06-01T00:00Z"

        val flights = Flights(List(
          ArrivalGenerator.apiFlight(flightId = 1, schDt = scheduled, iata = "BA0001", terminal = "T1", actPax = 1)
        ))

        val fiveMinutes = 600d / 60
        val procTimes: Map[PaxTypeAndQueue, Double] = Map(eeaMachineReadableToDesk -> fiveMinutes)

        val crunch = runCrunchGraph(
          procTimes = procTimes,
          crunchStartDateProvider = (_) => SDate("2017-05-31T23:00Z"),
          crunchEndDateProvider = (_) => SDate("2017-05-31T23:00Z").addMinutes(120),
          minMaxDesks = minMaxDesks
        )

        crunch.liveArrivalsInput.offer(flights)

        val result = crunch.liveTestProbe.expectMsgAnyClassOf(5 seconds, classOf[PortState])
        val resultSummary = deskRecsFromPortState(result, 120)

        val expected = Map("T1" -> Map(Queues.EeaDesk -> Seq(
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
          5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
          5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5
        )))

        resultSummary === expected
      }

      "Given a list of Min or Max desks" >> {
        "When parsing a BST date then we should get BST min/max desks" >> {
          val testMaxDesks = List(0, 1, 2, 3, 4, 5)
          val startTimeMidnightBST = SDate("2017-06-01T00:00Z").addHours(-1).millisSinceEpoch

          val oneHour = oneMinute * 60
          val startTimes = startTimeMidnightBST to startTimeMidnightBST + (oneHour * 5) by oneHour

          val expected = List(0, 1, 2, 3, 4, 5)
          startTimes.map(desksForHourOfDayInUKLocalTime(_, testMaxDesks)) === expected
        }
        "When parsing a GMT date then we should get BST min/max desks" >> {
          val testMaxDesks = List(0, 1, 2, 3, 4, 5)
          val startTimeMidnightGMT = SDate("2017-01-01T00:00Z").millisSinceEpoch

          val oneHour = oneMinute * 60
          val startTimes = startTimeMidnightGMT to startTimeMidnightGMT + (oneHour * 5) by oneHour

          val expected = List(0, 1, 2, 3, 4, 5)
          startTimes.map(desksForHourOfDayInUKLocalTime(_, testMaxDesks)) === expected
        }
      }
    }
  }
}
