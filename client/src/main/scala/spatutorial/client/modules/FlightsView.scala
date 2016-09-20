package spatutorial.client.modules

import diode.data.Pot
import diode.react.{ReactPot, ReactConnectProxy, ModelProxy}
import japgolly.scalajs.react.ReactComponentB
import japgolly.scalajs.react.extra.router.RouterCtl
import spatutorial.client.SPAMain.Loc
import spatutorial.client.components.Bootstrap.Panel
import spatutorial.client.services.RequestFlights
import spatutorial.shared.ApiFlight
import spatutorial.shared.FlightsApi.Flights
import japgolly.scalajs.react._
import japgolly.scalajs.react.extra.router.RouterCtl
import japgolly.scalajs.react.vdom.prefix_<^._
import spatutorial.client.logger._
import diode.react.ReactPot._
import diode.data.Pot
import diode.react._
import diode.util._
import japgolly.scalajs.react._
import japgolly.scalajs.react.extra.router.RouterCtl
import japgolly.scalajs.react.vdom.prefix_<^._
import spatutorial.client.SPAMain.{Loc, TodoLoc}
import spatutorial.client.components.Bootstrap.Panel
import spatutorial.client.components._
import spatutorial.client.services.{Crunch, GetWorkloads, Workloads}
import spatutorial.shared.FlightsApi.Flights
import spatutorial.shared.{CrunchResult, SimulationResult}

import scala.scalajs.js
import scala.util.Random
import scala.language.existentials
import spatutorial.client.logger._

object FlightsView {

  import scala.language.existentials

  case class Props(router: RouterCtl[Loc], flightsModelProxy: ModelProxy[Pot[Flights]])

  case class State(flights: ReactConnectProxy[Pot[Flights]])

  val component = ReactComponentB[Props]("Flights")
    .initialState_P(p =>
      State(p.flightsModelProxy.connect(m => m))
    ).renderPS((_, proxy, state) => Panel(Panel.Props("Flights"),
    <.h2("Flights"),
    state.flights(x => {
      <.div(^.className := "table-responsive",
        proxy.flightsModelProxy.value.renderReady(flights =>
          <.table(^.className := "table", ^.className := "table-striped",
            flightHeaders, <.tbody( flights.flights.sortBy(_.Operator).reverse.map(flightRow) ))))
    }))).componentDidMount((scope) => Callback.when(scope.props.flightsModelProxy.value.isEmpty) {
    log.info("Flights View is empty, requesting flights")
    scope.props.flightsModelProxy.dispatch(RequestFlights(0, 0))
  }).build

  def flightHeaders() = {
    val hs = List("Operator",
      "Status",
      "EstDT",
      "ActDT",
      "EstChoxDT",
      "ActChoxDT",
      "Gate",
      "Stand",
      "MaxPax",
      "ActPax",
      "TranPax",
      "RunwayID",
      "BaggageReclaimId",
      "FlightID",
      "AirportID",
      "Terminal",
      "ICAO",
      "IATA",
      "Origin",
      "SchDT")
    <.thead(hs.map(<.th(_)))
  }

  def flightRow(f: ApiFlight) = {
    val vals = List(
      <.td(f.Operator),
      <.td(f.Status),
      <.td(f.EstDT),
      <.td(f.ActDT),
      <.td(f.EstChoxDT),
      <.td(f.ActChoxDT),
      <.td(f.Gate),
      <.td(f.Stand),
      <.td(f.MaxPax.toString),
      <.td(f.ActPax.toString),
      <.td(f.TranPax.toString),
      <.td(f.RunwayID),
      <.td(f.BaggageReclaimId),
      <.td(f.FlightID.toString),
      <.td(f.AirportID),
      <.td(f.Terminal),
      <.td(f.ICAO),
      <.td(f.IATA),
      <.td(f.Origin, ^.title:=Callback."portname"),
      <.td(f.SchDT))

    <.tr(vals)
  }

  def apply(props: Props, proxy: ModelProxy[Pot[Flights]]) = component(props)
}