package actors

import akka.actor._
import akka.util.Timeout
import controllers.FlightState
import org.joda.time.LocalDate
import org.joda.time.format.DateTimeFormat
import spatutorial.shared.FlightsApi.Flights

import scala.concurrent.duration._
import scala.language.postfixOps

case object GetFlights


class FlightsActor(crunchActor: ActorRef) extends Actor with ActorLogging  with FlightState {
  implicit val timeout = Timeout(5 seconds)

  def receive = {
    case GetFlights =>
      log.info(s"Being asked for flights and I know about ${flights.size}")
      sender ! Flights(flights.values.toList)
    case Flights(newFlights) =>
      log.info(s"Adding ${newFlights.length} new flights")
      val formatter = DateTimeFormat.forPattern("yyyy-MM-dd")
      val lastMidnight = LocalDate.now().toString(formatter)
      onFlightUpdates(newFlights, lastMidnight)
      crunchActor ! PerformCrunchOnFlights(newFlights)
    case message => log.error("Actor saw unexpected message: " + message.toString)
  }
}