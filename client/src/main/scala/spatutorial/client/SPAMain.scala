package spatutorial.client

import chandu0101.scalajs.react.components.ReactTable
import diode.data.{Empty, Pot, PotState, Ready}
import diode.react.{ModelProxy, ReactConnectProxy}
import japgolly.scalajs.react.extra.router.StaticDsl.{DynamicRouteB, Rule}
import japgolly.scalajs.react.{ReactDOM, _}
import japgolly.scalajs.react.extra.router._
import japgolly.scalajs.react.vdom.ReactTagOf
import japgolly.scalajs.react.vdom.prefix_<^._
import org.scalajs.dom
import spatutorial.client.components.TableTerminalDeskRecs.{QueueDetailsRow, TerminalUserDeskRecsRow}
import spatutorial.client.components.{DeskRecsChart, GlobalStyles, Layout, MainMenu, QueueUserDeskRecsComponent, Staffing, TableTerminalDeskRecs, TerminalPage}
import spatutorial.client.logger._
import spatutorial.client.modules.Dashboard.{DashboardModels, QueueCrunchResults}
import spatutorial.client.modules.FlightsView._
import spatutorial.client.modules.{FlightsView, _}
import spatutorial.client.services.HandyStuff.{PotCrunchResult, QueueStaffDeployments}
import spatutorial.client.services._
import spatutorial.shared._
import spatutorial.shared.FlightsApi.{Flights, QueueName, TerminalName}

import scala.collection.immutable.{IndexedSeq, Map, Seq}
import scala.scalajs.js
import scala.scalajs.js.annotation.JSExport
import scalacss.Defaults._

object TableViewUtils {

  val eeadesk: QueueName = "eeaDesk"
  val noneeadesk: QueueName = "nonEeaDesk"
  val egate: QueueName = "eGate"

  def queueNameMappingOrder = eeadesk :: noneeadesk :: egate :: Nil

  def queueDisplayName = Map(eeadesk -> "EEA", noneeadesk -> "Non-EEA", egate -> "e-Gates")

  def terminalUserDeskRecsRows(
                                timestamps: Seq[Long],
                                paxload: Map[String, List[Double]],
                                queueCrunchResultsForTerminal: Map[QueueName, Pot[PotCrunchResult]],
                                simulationResult: Map[QueueName, Pot[SimulationResult]],
                                userDeskRec: QueueStaffDeployments
                              ): List[TerminalUserDeskRecsRow] = {
    log.info(s"call terminalUserDeskRecsRows")
    val queueRows: List[List[((Long, QueueName), QueueDetailsRow)]] = queueNameMappingOrder.map(queueName => {
      simulationResult.get(queueName) match {
        case Some(Ready(sr)) =>
          val result = queueNosFromSimulationResult(timestamps, paxload, queueCrunchResultsForTerminal, userDeskRec, simulationResult, queueName)
          log.info(s"before transpose it is ${result}")
          log.info(s"before transpose it is ${result.map(_.length)}")
          queueDetailsRowsFromNos(queueName, result)
        case None =>
          queueCrunchResultsForTerminal.get(queueName) match {
            case Some(Ready(cr)) =>
              queueDetailsRowsFromNos(queueName, queueNosFromCrunchResult(timestamps, paxload, queueCrunchResultsForTerminal, userDeskRec, queueName))
            case _ =>
              List()
          }
      }
    })

    val queueRowsByTime = queueRows.flatten.groupBy(tqr => tqr._1._1)

    queueRowsByTime.map((queueRows: (Long, List[((Long, QueueName), QueueDetailsRow)])) => {
      val qr = queueRows._2.map(_._2)
      TerminalUserDeskRecsRow(queueRows._1, qr)
    }).toList.sortWith(_.time < _.time)
  }

  def queueDetailsRowsFromNos(qn: QueueName, queueNos: Seq[List[Long]]): List[((Long, String), QueueDetailsRow)] = {
    queueNos.toList.transpose.zipWithIndex.map {
      case ((timestamp :: pax :: _ :: crunchDeskRec :: userDeskRec :: waitTimeCrunch :: waitTimeUser :: Nil), rowIndex) =>
        (timestamp, qn) -> QueueDetailsRow(
          timestamp = timestamp,
          pax = pax.toDouble,
          crunchDeskRec = crunchDeskRec.toInt,
          userDeskRec = DeskRecTimeslot(timestamp, userDeskRec.toInt),
          waitTimeWithCrunchDeskRec = waitTimeCrunch.toInt,
          waitTimeWithUserDeskRec = waitTimeUser.toInt,
          qn
        )
    }
  }

  private val numberOf15MinuteSlots = 96

  def queueNosFromSimulationResult(timestamps: Seq[Long], paxload: Map[String, List[Double]],
                                   queueCrunchResultsForTerminal: QueueCrunchResults,
                                   userDeskRec: QueueStaffDeployments,
                                   simulationResult: Map[QueueName, Pot[SimulationResult]], qn: QueueName
                                  ): Seq[List[Long]] = {
    val ts = DeskRecsChart.takeEvery15th(timestamps).take(numberOf15MinuteSlots).toList

    log.info(s"queueNosFromSimulationResult queueCrunch ${queueCrunchResultsForTerminal}")
    log.info(s"queueNosFromSimulationResult userDeskRec ${userDeskRec}")
    Seq(
      ts,
      paxload(qn).grouped(15).map(paxes => paxes.sum.toLong).toList,
      simulationResult(qn).get.recommendedDesks.map(rec => rec.time).grouped(15).map(_.min).toList,
      queueCrunchResultsForTerminal(qn).get.get.recommendedDesks.map(_.toLong).grouped(15).map(_.max).toList,
      getSafeUserDeskRecs(userDeskRec, qn, ts),
      queueCrunchResultsForTerminal(qn).get.get.waitTimes.map(_.toLong).grouped(15).map(_.max).toList,
      simulationResult(qn).get.waitTimes.map(_.toLong).grouped(15).map(_.max).toList
    )
  }


  def queueNosFromCrunchResult(timestamps: Seq[Long], paxload: Map[String, List[Double]],
                               queueCrunchResultsForTerminal: QueueCrunchResults,
                               userDeskRec: QueueStaffDeployments, qn: QueueName
                              ): Seq[List[Long]] = {
//    log.info(s"queueNosFromCrunchResult: userDeskRecs: ${userDeskRec(qn).get.items.map(_.deskRec.toLong).grouped(15).map(_.max).toList}")
    val ts = DeskRecsChart.takeEvery15th(timestamps).take(numberOf15MinuteSlots).toList
    val userDeskRecsSample: List[Long] = getSafeUserDeskRecs(userDeskRec, qn, ts)

    Seq(
      DeskRecsChart.takeEvery15th(timestamps).take(numberOf15MinuteSlots).toList,
      paxload(qn).grouped(15).map(paxes => paxes.sum.toLong).toList,
      List.range(0, queueCrunchResultsForTerminal(qn).get.get.recommendedDesks.length, 15).map(_.toLong),
      queueCrunchResultsForTerminal(qn).get.get.recommendedDesks.map(_.toLong).grouped(15).map(_.max).toList,
      userDeskRecsSample,
      queueCrunchResultsForTerminal(qn).get.get.waitTimes.map(_.toLong).grouped(15).map(_.max).toList,
      queueCrunchResultsForTerminal(qn).get.get.waitTimes.map(_.toLong).grouped(15).map(_.max).toList
    )
  }

  def getSafeUserDeskRecs(userDeskRec: QueueStaffDeployments, qn: QueueName, ts: List[Long]) = {
    val queueUserDeskRecs = userDeskRec.get(qn)
    val userDeskRecsSample = queueUserDeskRecs match {
      case Some(Ready(udr)) => udr.items.map(_.deskRec.toLong).toList
      case _ => List.fill(ts.length)(0L)
    }
    userDeskRecsSample
  }


}

@JSExport("SPAMain")
object SPAMain extends js.JSApp {

  // Define the locations (pages) used in this application
  sealed trait Loc

  case object DashboardLoc extends Loc

  case object FlightsLoc extends Loc

  case object UserDeskRecommendationsLoc extends Loc

  case class TerminalUserDeskRecommendationsLoc(terminalName: TerminalName) extends Loc

  case class TerminalLoc(id: String) extends Loc

  case object StaffingLoc extends Loc

  val initActions = GetWorkloads("", "") :: GetAirportConfig() :: RequestFlights(0, 0) :: GetShifts() :: Nil
  initActions.foreach(SPACircuit.dispatch(_))

  // configure the router
  val routerConfig = RouterConfigDsl[Loc].buildConfig { dsl =>
    import dsl._
    val dashboardModelsConnect = SPACircuit.connect(m =>
      DashboardModels(m.workload, m.queueCrunchResults, m.simulationResult))
    val airportConfigPotRCP: ReactConnectProxy[Pot[AirportConfig]] = SPACircuit.connect(_.airportConfig)

    val dashboardRoute = staticRoute("#charts", DashboardLoc) ~>
      renderR(ctl => dashboardModelsConnect(proxy => {
        log.info("charts update")
        airportConfigPotRCP(airportConfigPotMP =>
          Dashboard(ctl, proxy, airportConfigPotMP())
        )
      }))

    val rootRoute = staticRoute(root, FlightsLoc) ~>
      renderR(ctl => {
        val airportWrapper = SPACircuit.connect(_.airportInfos)
        val flightsWrapper = SPACircuit.connect(m => m.flights)
        airportWrapper(airportInfoProxy => flightsWrapper(proxy => FlightsView(Props(proxy.value, airportInfoProxy.value))))
      })

    val flightsRoute = staticRoute("#flights", FlightsLoc) ~>
      renderR(ctl => {
        val airportWrapper = SPACircuit.connect(_.airportInfos)
        val flightsWrapper = SPACircuit.connect(m => m.flights)
        airportWrapper(airportInfoProxy => flightsWrapper(proxy => FlightsView(Props(proxy.value, airportInfoProxy.value))))
      })


    val terminals = dynamicRouteCT("#terminal" / string("[a-zA-Z0-9]+")
      .caseClass[TerminalLoc]) ~> dynRenderR((page: TerminalLoc, ctl) => TerminalPage(page.id, ctl))

    val userDeskRecsRoute = staticRoute("#userdeskrecs", UserDeskRecommendationsLoc) ~> renderR(ctl => {
      //todo take the queuenames from the workloads response
      log.info("running our user desk recs route")

      QueueUserDeskRecsComponent.terminalQueueUserDeskRecsComponent()
    })

    val staffing = staticRoute("#staffing", StaffingLoc) ~>
      renderR(ctl => {
        Staffing()
      })

    val rule = rootRoute | dashboardRoute | flightsRoute | userDeskRecsRoute | terminals | staffing
    rule.notFound(redirectToPage(DashboardLoc)(Redirect.Replace))
  }.renderWith(layout)

  // base layout for all pages
  def layout(c: RouterCtl[Loc], r: Resolution[Loc]) = {
    Layout(c, r)
  }

  def pathToThisApp: String = dom.document.location.pathname

  @JSExport
  def main(): Unit = {
    //    Perf.start()
    //    scala.scalajs.js.Dynamic.global.window.Perf = Perf;
    log.warn("Application starting")
    // send log messages also to the server
    log.enableServerLogging(pathToThisApp + "/logging")
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
