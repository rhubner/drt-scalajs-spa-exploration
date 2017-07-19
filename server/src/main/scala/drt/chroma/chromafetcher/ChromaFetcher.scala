package drt.chroma.chromafetcher

import akka.actor.ActorSystem
import drt.chroma.chromafetcher.ChromaFetcher.{ChromaToken, ChromaSingleFlight}
import drt.chroma.ChromaConfig
import drt.http.WithSendAndReceive
import org.slf4j.LoggerFactory
import spray.client.pipelining._
import spray.http.HttpHeaders.{Accept, Authorization}
import spray.http.{HttpRequest, HttpResponse, MediaTypes, OAuth2BearerToken}
import spray.httpx.SprayJsonSupport // intellij may try to remove this, don't let it or unmarshall will stop working
import spray.json.DefaultJsonProtocol

import scala.collection.immutable.Seq
import scala.concurrent.duration.{Duration, _}
import scala.concurrent.{Await, Future}

object ChromaFetcher {

  case class ChromaToken(access_token: String, token_type: String, expires_in: Int)
  case class AzureToken(access_token: String, token_type: String, expires_in: String)

  case class ChromaSingleFlight(Operator: String,
                                Status: String,
                                EstDT: String,
                                ActDT: String,
                                EstChoxDT: String,
                                ActChoxDT: String,
                                Gate: String,
                                Stand: String,
                                MaxPax: Int,
                                ActPax: Int,
                                TranPax: Int,
                                RunwayID: String,
                                BaggageReclaimId: String,
                                FlightID: Int,
                                AirportID: String,
                                Terminal: String,
                                ICAO: String,
                                IATA: String,
                                Origin: String,
                                SchDT: String)
}

trait ChromaFetcher extends ChromaConfig with WithSendAndReceive {
  implicit val system: ActorSystem

  import system.dispatcher
  import ChromaParserProtocol._

  def log = LoggerFactory.getLogger(classOf[ChromaFetcher])

  val logResponse: HttpResponse => HttpResponse = { resp =>
    log.info(s"Response Object: $resp")
    log.debug(s"Response: ${resp.entity.asString}")
    if (resp.status.isFailure) {
      log.warn(s"Failed to talk to chroma ${resp.headers}")
      log.warn(s"Failed to talk to chroma: entity ${resp.entity.data.asString}")
    }

    resp
  }

  def tokenPipeline: HttpRequest => Future[ChromaToken] = (
    addHeader(Accept(MediaTypes.`application/json`))
      ~> sendAndReceive
      ~> logResponse
      ~> unmarshal[ChromaToken]
    )

  case class livePipeline(token: String) {

    val pipeline: (HttpRequest => Future[List[ChromaSingleFlight]]) = {
      log.info(s"Sending request for $token")
      val logRequest: HttpRequest => HttpRequest = { r => log.debug(r.toString); r }

      {
        val resp = addHeaders(Accept(MediaTypes.`application/json`), Authorization(OAuth2BearerToken(token))) ~>
          logRequest ~>
          sendAndReceive ~>
          logResponse
        resp ~> unmarshal[List[ChromaSingleFlight]]
      }
    }
  }

  def currentFlights: Future[Seq[ChromaSingleFlight]] = {
    val eventualToken: Future[ChromaToken] = tokenPipeline(Post(tokenUrl, chromaTokenRequestCredentials))
    def eventualLiveFlights(accessToken: String): Future[List[ChromaSingleFlight]] = livePipeline(accessToken).pipeline(Get(url))

    for {
      t <- eventualToken
      chromaResponse <- eventualLiveFlights(t.access_token)
    } yield {
      chromaResponse
    }
  }

  def currentFlightsBlocking: Seq[ChromaSingleFlight] = {
    Await.result(currentFlights, Duration(10, SECONDS))
  }
}



