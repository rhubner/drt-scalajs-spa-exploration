package feeds.lhr.live

import akka.actor.ActorSystem
import akka.testkit.TestKit
import akka.util.Timeout
import com.typesafe.config.ConfigFactory
import drt.server.feeds.lhr.live.LHRLiveFeed
import drt.shared.Arrival
import org.specs2.mutable.SpecificationLike
import services.SDate
import spray.http.{HttpEntity, _}

import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration._
import scala.concurrent.{Await, Future}

class LHRMailLiveFeedSpec extends TestKit(ActorSystem("testActorSystem", ConfigFactory.empty())) with SpecificationLike {

  import drt.server.feeds.lhr.live.LHRLiveFeed._

  implicit val timeout = Timeout(1 second)

  "When processing the LHR flight feed" +
    "Given a response with 2 flights in json format then I should get back a list of 2 LHR Live Arrivals" >> {

    val consumer = new LHRLiveFeedConsumer("", "fake security", system) with MockSuccessfulFlightData
    val response = consumer.flights

    val result = Await.result(response, 1 second).flatten

    val expected = List(
      LHRLiveArrival(
        "FL002", "T2", "LB", "1", "FL", "764", "JNB", "ZA", "2018-02-12 10:20:00",
        "2018-02-12 09:53:43", "2018-02-12 10:03:00", "2018-02-12 10:02:00"
      ),
      LHRLiveArrival("FL001", "T2", "SH", "2", "FL", "73H", "JNB", "ZA", "2018-02-12 18:20:00", "", "", "")
    )

    result === expected
  }

  "When processing the LHR passenger feed" +
    "Given a response with pax numbers for 2 flights in json format then I should get back a list of 2 LHRFlightPax" >> {


    val consumer = new LHRLiveFeedConsumer("", "fake security", system) with MockSuccessfulFlightData
    val response = consumer.pax

    val result = Await.result(response, 1 second).flatten

    val expected = List(
      LHRFlightPax(
        "FL002", "2018-02-12 10:20:00", "469", "414", "200", "218", "0", "1", "58", "0", "0", "0", "125", "32"
      ),
      LHRFlightPax(
        "FL001", "2018-02-12 18:20:00", "214", "163", "63", "104", "2", "1", "10", "0", "1", "0", "82", "6"
      )
    )

    result === expected
  }

  "When handling date formats in the feed" >> {
    "Given a date format with a missing T then we should handle parse it and convert it to an ISO date" >> {
      val badDate = "2018-02-12 09:53:43"
      val expected = "2018-02-12T09:53:43Z"

      val result = LHRLiveFeed.dateStringToIsoString(badDate)

      result === expected
    }
    "Given a date format with a T then we should handle parse it and convert it to an ISO date" >> {
      val badDate = "2018-02-12T09:53:43"
      val expected = "2018-02-12T09:53:43Z"

      val result = LHRLiveFeed.dateStringToIsoString(badDate)

      result === expected
    }
    "Given and empty string then we should get back an empty string" >> {
      val badDate = ""
      val expected = ""

      val result = LHRLiveFeed.dateStringToIsoString(badDate)

      result === expected
    }
  }

  "When processing the LHR Feed" >> {

    "Given a LHR Arrival and LHR Pax count then I should get back an Arrival with the data from both combined" >> {
      val lhrArrival = LHRLiveArrival(
        "FL002", "T2", "LB", "1", "FL", "764", "JNB", "ZA", "2018-02-12 10:20:00",
        "2018-02-12 09:53:43", "2018-02-12 10:03:00", "2018-02-12 10:02:00"
      )

      val lhrPax = LHRFlightPax(
        "FL002", "2018-02-12T10:20:00", "469", "414", "200", "218", "0", "1", "58", "0", "0", "0", "125", "32"
      )

      val result: Arrival = LHRLiveFeed.flightAndPaxToArrival(lhrArrival, Option(lhrPax)).get

      val expected = Arrival(
        "FL", "Last Bag", "2018-02-12T09:53:43Z", "", "2018-02-12T10:03:00Z", "2018-02-12T10:02:00Z", "", "1", 469, 414,
        218, "", "", 0, "LHR", "T2", "FL002", "FL002", "JNB", "2018-02-12T10:20:00Z",
        SDate("2018-02-12T10:20:00").millisSinceEpoch, 0, None
      )

      result === expected
    }

    "Given two LHR Arrivals but no pax count then I should get back an Arrival with 0 pax" >> {
      val lhrArrival = LHRLiveArrival(
        "FL002", "T2", "LB", "1", "FL", "764", "JNB", "ZA", "2018-02-12 10:20:00",
        "2018-02-12 09:53:43", "2018-02-12 10:03:00", "2018-02-12 10:02:00"
      )

      val lhrPax = LHRFlightPax(
        "FL002", "2018-02-12T10:20:00", "469", "414", "200", "218", "0", "1", "58", "0", "0", "0", "125", "32"
      )

      val result: Arrival = LHRLiveFeed.flightAndPaxToArrival(lhrArrival, None).get

      val expected = Arrival(
        "FL", "Last Bag", "2018-02-12T09:53:43Z", "", "2018-02-12T10:03:00Z", "2018-02-12T10:02:00Z", "", "1", 0, 0,
        0, "", "", 0, "LHR", "T2", "FL002", "FL002", "JNB", "2018-02-12T10:20:00Z",
        SDate("2018-02-12T10:20:00").millisSinceEpoch, 0, None
      )

      result === expected
    }
  }

  "When processing the LHR feed" >> {
    "Given a response with pax numbers and flights in json format then I should get back a list Arrivals with pax included" >> {


      val consumer = new LHRLiveFeedConsumer("", "fake security", system) with MockSuccessfulFlightData
      val response = consumer.arrivals

      val result = Await.result(response, 1 second)

      val expected = List(
        Arrival(
          "FL", "Last Bag", SDate("2018-02-12T09:53:43").toISOString, "", SDate("2018-02-12T10:03:00").toISOString,
          SDate("2018-02-12T10:02:00").toISOString, "", "1", 469, 414, 218, "", "", 0, "LHR", "T2", "FL002", "FL002",
          "JNB", SDate("2018-02-12T10:20:00").toISOString,
          SDate("2018-02-12T10:20:00").millisSinceEpoch, 0, None
        ),
        Arrival(
          "FL", "Scheduled", "", "", "", "", "", "2", 214, 163, 104, "", "", 0, "LHR", "T2", "FL001", "FL001", "JNB",
          "2018-02-12T18:20:00Z", SDate("2018-02-12T18:20:00").millisSinceEpoch, 0, None
        )
      )

      result.toSet === expected.toSet
    }

    "Given a successful response for flights, but a rate limit exceeded response for pax numbers " +
      "then I should get flights back with 0 pax numbers" >> {


      val consumer = new LHRLiveFeedConsumer("", "fake security", system) with MockSuccessfulFlightDataWithRateLimitedPax
      val response = consumer.arrivals

      val result = Await.result(response, 1 second)

      val expected = List(
        Arrival(
          "FL", "Last Bag", SDate("2018-02-12T09:53:43").toISOString, "", SDate("2018-02-12T10:03:00").toISOString,
          SDate("2018-02-12T10:02:00").toISOString, "", "1", 0, 0, 0, "", "", 0, "LHR", "T2", "FL002", "FL002", "JNB",
          SDate("2018-02-12T10:20:00").toISOString(),
          SDate("2018-02-12T10:20:00").millisSinceEpoch, 0, None
        ),
        Arrival(
          "FL", "Scheduled", "", "", "", "", "", "2", 0, 0, 0, "", "", 0, "LHR", "T2", "FL001", "FL001", "JNB",
          SDate("2018-02-12T18:20:00").toISOString, SDate("2018-02-12T18:20:00").millisSinceEpoch, 0, None
        )
      )

      result.toSet === expected.toSet
    }

    "Given a rate limit exceeded response for flights, and a rate limit exceeded response for pax numbers " +
      "then I should get and empty list" >> {


      val consumer = new LHRLiveFeedConsumer("", "fake security", system) with MockRateLimitedEverything
      val response = consumer.arrivals

      val result = Await.result(response, 1 second)

      val expected = List()

      result === expected
    }

    "Given successful response for flights with malformed content then I should get and empty list" >> {


      val consumer = new LHRLiveFeedConsumer("", "fake security", system) with MockMalformedContentReponse
      val response = consumer.arrivals

      val result = Await.result(response, 1 second)

      val expected = List()

      result === expected
    }
  }

  trait MockSuccessfulFlightData {

    def sendAndReceive: (HttpRequest) => Future[HttpResponse] = (req: HttpRequest) => {
      val responseText = req.uri.toString() match {
        case "/arrivaldata/api/Flights/getflightsdetails/0/1" => successFullFlightsResponse
        case "/arrivaldata/api/Passenger/GetPassengerCount/0/1" => successFullPaxResponse
      }

      Future(HttpResponse().withEntity(HttpEntity(ContentTypes.`application/json`, responseText)))
    }
  }

  trait MockMalformedContentReponse {

    def sendAndReceive: (HttpRequest) => Future[HttpResponse] = (req: HttpRequest) => {
      val responseText =
        """
          |[["data":"broken"]]
        """.stripMargin

      Future(HttpResponse().withEntity(HttpEntity(ContentTypes.`application/json`, responseText)))
    }
  }

  trait MockRateLimitedEverything {

    def sendAndReceive: (HttpRequest) => Future[HttpResponse] = (req: HttpRequest) => {
      Future(
        HttpResponse(StatusCodes.TooManyRequests)
          .withEntity(HttpEntity(ContentTypes.`application/json`, rateLimitResponse))
      )
    }
  }

  trait MockSuccessfulFlightDataWithRateLimitedPax {

    def sendAndReceive: (HttpRequest) => Future[HttpResponse] = (req: HttpRequest) => {
      req.uri.toString() match {
        case "/arrivaldata/api/Flights/getflightsdetails/0/1" =>
          Future(HttpResponse().withEntity(HttpEntity(ContentTypes.`application/json`, successFullFlightsResponse)))
        case "/arrivaldata/api/Passenger/GetPassengerCount/0/1" =>
          Future(
            HttpResponse(StatusCodes.TooManyRequests)
              .withEntity(HttpEntity(ContentTypes.`application/json`, rateLimitResponse))
          )
      }
    }
  }

  val rateLimitResponse =
    """
      |{
      |  "statusCode": 429,
      |  "message": "Rate limit is exceeded. Try again in 282 seconds."
      |}
    """.stripMargin

  val successFullFlightsResponse =
    """
      |[[
      |  {
      |      "FLIGHTNUMBER": "FL002",
      |      "TERMINAL": "T2",
      |      "FLIGHTSTATUS": "LB",
      |      "STAND": "1",
      |      "OPERATOR": "FL",
      |      "AIRCRAFTTYPE": "764",
      |      "AIRPORTCODE": "JNB",
      |      "COUNTRYCODE": "ZA",
      |      "SCHEDULEDFLIGHTOPERATIONTIME": "2018-02-12 10:20:00",
      |      "ESTIMATEDFLIGHTOPERATIONTIME": "2018-02-12 09:53:43",
      |      "ESTIMATEDFLIGHTCHOXTIME": "2018-02-12 10:03:00",
      |      "ACTUALFLIGHTCHOXTIME": "2018-02-12 10:02:00"
      |  },
      |  {
      |      "FLIGHTNUMBER": "FL001",
      |      "TERMINAL": "T2",
      |      "FLIGHTSTATUS": "SH",
      |      "STAND": "2",
      |      "OPERATOR": "FL",
      |      "AIRCRAFTTYPE": "73H",
      |      "AIRPORTCODE": "JNB",
      |      "COUNTRYCODE": "ZA",
      |      "SCHEDULEDFLIGHTOPERATIONTIME": "2018-02-12 18:20:00",
      |      "ESTIMATEDFLIGHTOPERATIONTIME": "",
      |      "ESTIMATEDFLIGHTCHOXTIME": "",
      |      "ACTUALFLIGHTCHOXTIME": ""
      |  }
      |]]
    """.stripMargin

  val successFullPaxResponse =
    """
      |[[
      |    {
      |      "FLIGHTNUMBER": "FL002",
      |      "SCHEDULEDFLIGHTOPERATIONTIME": "2018-02-12 10:20:00",
      |      "MAXPASSENGERCOUNT": "469",
      |      "TOTALPASSENGERCOUNT": "414",
      |      "ACTUALDIRECTPASSENGERCOUNT": "200",
      |      "ACTUALTRANSFERPASSENGERCOUNT": "218",
      |      "ACTUALT2INTCOUNT": "0",
      |      "ACTUALT2DOMCOUNT": "1",
      |      "ACTUALT3INTCOUNT": "58",
      |      "ACTUALT3DOMCOUNT": "0",
      |      "ACTUALT4INTCOUNT": "0",
      |      "ACTUALT4DOMCOUNT": "0",
      |      "ACTUALT5INTCOUNT": "125",
      |      "ACTUALT5DOMCOUNT": "32"
      |    },
      |    {
      |      "FLIGHTNUMBER": "FL001",
      |      "SCHEDULEDFLIGHTOPERATIONTIME": "2018-02-12 18:20:00",
      |      "MAXPASSENGERCOUNT": "214",
      |      "TOTALPASSENGERCOUNT": "163",
      |      "ACTUALDIRECTPASSENGERCOUNT": "63",
      |      "ACTUALTRANSFERPASSENGERCOUNT": "104",
      |      "ACTUALT2INTCOUNT": "2",
      |      "ACTUALT2DOMCOUNT": "1",
      |      "ACTUALT3INTCOUNT": "10",
      |      "ACTUALT3DOMCOUNT": "0",
      |      "ACTUALT4INTCOUNT": "1",
      |      "ACTUALT4DOMCOUNT": "0",
      |      "ACTUALT5INTCOUNT": "82",
      |      "ACTUALT5DOMCOUNT": "6"
      |    }
      |]]
    """.stripMargin
}
