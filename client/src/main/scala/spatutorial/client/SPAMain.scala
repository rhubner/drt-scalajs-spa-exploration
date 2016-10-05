package spatutorial.client

import chandu0101.scalajs.react.components.ReactTable
import diode.{ModelR, UseValueEq}
import diode.data.{Empty, Pot, Ready}
import diode.react.ReactConnectProxy
import japgolly.scalajs.react.{ReactDOM, _}
import japgolly.scalajs.react.extra.router._
import japgolly.scalajs.react.vdom.prefix_<^._
import org.scalajs.dom
import spatutorial.client.components.TableTodoList.UserDeskRecsRow
import spatutorial.client.components.{DeskRecsChart, GlobalStyles, QueueUserDeskRecsComponent}
import spatutorial.client.logger._
import spatutorial.client.modules.Dashboard.DashboardModels
import spatutorial.client.modules.FlightsView._
import spatutorial.client.modules.{FlightsView, _}
import spatutorial.client.services._
import spatutorial.shared.{CrunchResult, DeskRec, SimulationResult}
import spatutorial.shared.FlightsApi.{QueueName, TerminalName}

import scala.collection.immutable.{IndexedSeq, NumericRange}
import scala.scalajs.js
import scala.scalajs.js.annotation.JSExport
import scalacss.Defaults._

@JSExport("SPAMain")
object SPAMain extends js.JSApp {

  // Define the locations (pages) used in this application
  sealed trait Loc

  case object DashboardLoc extends Loc

  case object FlightsLoc extends Loc

  case object UserDeskRecommendationsLoc extends Loc

  val eeadesk = "eeaDesk"
  val egate = "eGate"

  val hasWl: ModelR[RootModel, Pot[Workloads]] = SPACircuit.zoom(_.workload)
  hasWl.value match {
    case Empty => SPACircuit.dispatch(GetWorkloads("", "", "edi"))
    case default =>
      log.info(s"was $default")
  }

  import scala.scalajs.js.timers._
  import scala.concurrent.duration._
  import scala.concurrent.duration.FiniteDuration

  setInterval(FiniteDuration(10L, SECONDS)) {
    SPACircuit.dispatch(RequestFlights(0, 0))
  }
  // configure the router
  val routerConfig = RouterConfigDsl[Loc].buildConfig { dsl =>
    import dsl._
    val dashboardModelsConnect = SPACircuit.connect(m =>
      DashboardModels(m.workload, m.queueCrunchResults, m.simulationResult, m.userDeskRec))

    val dashboardRoute = staticRoute(root, DashboardLoc) ~>
      renderR(ctl => dashboardModelsConnect(proxy => {
        log.info("dashboard update")
        Dashboard(ctl, proxy)
      }))

    val flightsRoute = staticRoute("#flights", FlightsLoc) ~>
      renderR(ctl => {
        val airportWrapper = SPACircuit.connect(_.airportInfos)
        val flightsWrapper = SPACircuit.connect(m => m.flights)
        airportWrapper(airportInfoProxy => flightsWrapper(proxy => FlightsView(Props(proxy.value, airportInfoProxy.value))))
      })

    val todosRoute = staticRoute("#userdeskrecs", UserDeskRecommendationsLoc) ~> renderR(ctl => {
      //todo take the queuenames from the workloads response
      val queues: Seq[QueueName] = Seq(eeadesk, egate)
      val terminalNames: Seq[TerminalName] = Seq("A1", "A2")
      val queueUserDeskRecProps: Seq[QueueUserDeskRecsComponent.Props] = terminalNames.flatMap { terminalName =>
        queues.map { queueName =>
          val labels: ReactConnectProxy[Pot[IndexedSeq[String]]] = SPACircuit.connect(_.workload.map(_.labels))
          val queueCrunchResults: ReactConnectProxy[Pot[CrunchResult]] = SPACircuit.connect(_.queueCrunchResults.getOrElse(terminalName, Map()).getOrElse(queueName, Empty).flatMap(_._1))
          val queueUserDeskRecs: ReactConnectProxy[Pot[UserDeskRecs]] = SPACircuit.connect(_.userDeskRec.getOrElse(terminalName, Map()).getOrElse(queueName, Empty))
          val flightsWrapper = SPACircuit.connect(_.flights)
          val simulationResultWrapper = SPACircuit.connect(_.simulationResult.getOrElse(terminalName, Map()).getOrElse(queueName, Empty))
          val items: ReactConnectProxy[Pot[List[UserDeskRecsRow]]] = makeItems(terminalName, queueName)
          val airportInfo = SPACircuit.connect(_.airportInfos)
          QueueUserDeskRecsComponent.Props(terminalName,
            queueName,
            items,
            airportInfo,
            labels,
            queueCrunchResults,
            queueUserDeskRecs, flightsWrapper, simulationResultWrapper)
        }
      }


      //        .map {
      //        case Empty => SPACircuit.dispatch(GetWorkloads("", "", "edi"))
      //        case default =>
      //          log.info(s"was $default")
      //      }
      <.div(queueUserDeskRecProps.map(QueueUserDeskRecsComponent.component(_)))
    })

    (dashboardRoute | flightsRoute | todosRoute).notFound(redirectToPage(DashboardLoc)(Redirect.Replace))
  }.renderWith(layout)

  def makeItems(terminalName: TerminalName, queueName: QueueName): ReactConnectProxy[Pot[List[UserDeskRecsRow]]] = {
    def defaultSimulationResult: Ready[SimulationResult] = Ready(
      SimulationResult(List.fill(1440)(0).map(v => DeskRec(v.toLong, v)).toIndexedSeq,
        List.fill(1440)(0)))
    val items: ReactConnectProxy[Pot[List[UserDeskRecsRow]]] = SPACircuit.connect(model => {
      val potRows: Pot[List[List[Any]]] = for {
        times <- model.workload.map(_.timeStamps)
        qcr <- model.queueCrunchResults.getOrElse(terminalName, Map()).getOrElse(queueName, Empty)
        qur <- model.userDeskRec.getOrElse(terminalName, Map()).getOrElse(queueName, Empty)
        simres <- model.simulationResult.getOrElse(terminalName, Map()).getOrElse(queueName, defaultSimulationResult)
        potcr = qcr._1
        potdr = qcr._2
        cr <- potcr
        dr <- potdr
      } yield {
        val every15thRecDesk = DeskRecsChart.takeEvery15th(cr.recommendedDesks)
        val every15thCrunchWaitTime = cr.waitTimes.grouped(15).map(_.max)
        val every15thSimWaitTime = simres.waitTimes.grouped(15).map(_.max)
        val aDaysWorthOfTimes: Seq[Long] = DeskRecsChart.takeEvery15th(times).take(96)
        val allRows = ((aDaysWorthOfTimes :: every15thRecDesk :: qur.items :: every15thCrunchWaitTime :: every15thSimWaitTime :: Nil).transpose)
        allRows
      }
      val is: Pot[List[UserDeskRecsRow]] = for (rows <- potRows) yield {
        rows.map(row => row match {
          case (time: Long) :: (crunchDeskRec: Int) :: (userDeskRec: DeskRecTimeslot) :: (waitTimeWithUserDeskRec: Int) :: (waitTimeWithCrunchDeskRec: Int) :: Nil =>
            UserDeskRecsRow(time, crunchDeskRec, userDeskRec, waitTimeWithUserDeskRec, waitTimeWithCrunchDeskRec)
          case default =>
            log.error(s"match error $default")
            throw new Exception(s"fail on $default")
        })
      }
      is
    })
    items
  }


  // base layout for all pages
  def layout(c: RouterCtl[Loc], r: Resolution[Loc]) = {
    <.div(
      // here we use plain Bootstrap class names as these are specific to the top level layout defined here
      <.nav(^.className := "navbar navbar-inverse navbar-fixed-top",
        <.div(^.className := "container",
          <.div(^.className := "navbar-header", <.span(^.className := "navbar-brand", "DRT EDI Live Spike")),
          <.div(^.className := "collapse navbar-collapse", MainMenu(c, r.page)))),
      // currently active module is shown in this container
      <.div(^.className := "container", r.render()))

  }

  @JSExport
  def main(): Unit = {
    log.warn("Application starting")
    // send log messages also to the server
    log.enableServerLogging("/logging")
    log.info("This message goes to server as well")

    // create stylesheet
    import scalacss.ScalaCssReact._

    ReactTable.DefaultStyle.addToDocument()
    //    Spinner.Style.addToDocument()
    GlobalStyles.addToDocument()
    // create the router
    val router = Router(BaseUrl.until_#, routerConfig)
    // tell React to render the router in the document body
    ReactDOM.render(router(), dom.document.getElementById("root"))
  }
}
