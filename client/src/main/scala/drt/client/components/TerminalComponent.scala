package drt.client.components

import diode.data.{Pending, Pot}
import diode.react.ModelProxy
import drt.client.actions.Actions.{HideLoader, SetPointInTime, ShowLoader}
import drt.client.components.FlightComponents.SplitsGraph.splitsGraphComponentColoured
import drt.client.components.FlightComponents.paxComp
import drt.client.components.Heatmap.Series
import drt.client.components.TerminalHeatmaps._
import drt.client.logger.log
import drt.client.services.HandyStuff.QueueStaffDeployments
import drt.client.services.JSDateConversions.SDate
import drt.client.services.{SPACircuit, TimeRangeHours, Workloads}
import drt.shared.Crunch.CrunchState
import drt.shared.FlightsApi.{FlightsWithSplits, QueueName, TerminalName}
import drt.shared.Simulations.QueueSimulationResult
import drt.shared._
import japgolly.scalajs.react.extra.Reusability
import japgolly.scalajs.react.vdom.html_<^
import japgolly.scalajs.react.vdom.html_<^._
import japgolly.scalajs.react.{BackendScope, Callback, ScalaComponent}
import org.scalajs.dom

import scala.collection.immutable.Map
import scala.util.Try

object TerminalComponent {

  case class Props(terminalName: TerminalName)

  case class TerminalModel(
                            crunchStatePot: Pot[CrunchState],
                            airportConfig: Pot[AirportConfig],
                            airportInfos: Pot[AirportInfo],
                            simulationResult: Map[QueueName, QueueSimulationResult],
                            crunchResult: Map[QueueName, CrunchResult],
                            deployments: QueueStaffDeployments,
                            workloads: Workloads,
                            actualDesks: Map[QueueName, Map[Long, DeskStat]],
                            pointInTime: Option[SDateLike],
                            timeRangeHours: TimeRangeHours
                          )

  def render(props: Props) = {
    val modelRCP = SPACircuit.connect(model => TerminalModel(
      model.crunchStatePot,
      model.airportConfig,
      model.airportInfos.getOrElse(props.terminalName, Pending()),
      model.simulationResult.getOrElse(props.terminalName, Map()),
      model.queueCrunchResults.getOrElse(props.terminalName, Map()),
      model.staffDeploymentsByTerminalAndQueue.getOrElse(props.terminalName, Map()),
      model.workloadPot.getOrElse(Workloads(Map())),
      model.actualDeskStats.getOrElse(props.terminalName, Map()),
      model.pointInTime,
      model.timeRangeFilter
    ))

    modelRCP(modelMP => {
      val model = modelMP.value
      <.div(
        model.airportConfig.renderReady(airportConfig => {
          val terminalContentProps = TerminalContentComponent.Props(
            model.crunchStatePot,
            airportConfig,
            props.terminalName,
            model.airportInfos,
            model.simulationResult,
            model.crunchResult,
            model.deployments,
            model.workloads,
            model.actualDesks,
            model.timeRangeHours,
            model.pointInTime.getOrElse(SDate.today())
          )
          <.div(
            SnapshotSelector(SnapshotSelector.Props(model.pointInTime, props.terminalName)),
            TerminalContentComponent(terminalContentProps)
          )
        }
        )
      )
    })
  }

  implicit val propsReuse = Reusability.caseClass[Props]

  val component = ScalaComponent.builder[Props]("Terminal")
    .renderPS(($, props, state) => render(props))
      .componentDidUpdate(p => Callback.log("Updating Terminal Component"))
      .componentDidMount(p => Callback.log("Updating Terminal Component"))
    .build

  def apply(props: Props): VdomElement = {
    component(props)
  }
}


object HeatmapComponent {

  case class Props(
                    airportConfig: AirportConfig,
                    terminalName: TerminalName,
                    simulationResults: Map[QueueName, QueueSimulationResult]
                  ) {
    lazy val hash = simulationResults.values.map(_.hashCode).hashCode()
  }

  case class State(activeTab: String)

  implicit val propsReuse = Reusability.by((_: Props).hash)
  implicit val stateReuse = Reusability.caseClass[State]

  val component = ScalaComponent.builder[Props]("Heatmaps")
    .initialState(State("deskrecs"))
    .renderPS((scope, props, state) =>
      <.div({
        val seriesPot: Pot[List[Series]] = waitTimes(props.simulationResults, props.terminalName)
        val baseHeight = 120
        val heatmapQueuesHeight = props.airportConfig.queues(props.terminalName).length * 40
        val heatmapsContainerHeight = baseHeight + heatmapQueuesHeight
        <.div(^.height := s"${heatmapsContainerHeight}px",
          <.ul(^.className := "nav nav-tabs",
            <.li(^.className := "active", <.a(VdomAttr("data-toggle") := "tab", ^.href := "#deskrecs", "Desk recommendations"), ^.onClick --> scope.modState(_ => State("deskrecs"))),
            <.li(<.a(VdomAttr("data-toggle") := "tab", ^.href := "#workloads", "Workloads"), ^.onClick --> scope.modState(_ => State("workloads"))),
            <.li(<.a(VdomAttr("data-toggle") := "tab", ^.href := "#paxloads", "Paxloads"), ^.onClick --> scope.modState(_ => State("paxloads"))),
            <.li(seriesPot.renderReady(s => {
              <.a(VdomAttr("data-toggle") := "tab", ^.href := "#waits", "Wait times", ^.onClick --> scope.modState(_ => State("waits")))
            }))
          )
          ,
          <.div(^.className := "tab-content",
            <.div(^.id := "deskrecs", ^.className := "tab-pane fade in active",
              if (state.activeTab == "deskrecs") {
                heatmapOfStaffDeploymentDeskRecs(props.terminalName)
              } else ""),
            <.div(^.id := "workloads", ^.className := "tab-pane fade",
              if (state.activeTab == "workloads") {
                heatmapOfWorkloads(props.terminalName)
              } else ""),
            <.div(^.id := "paxloads", ^.className := "tab-pane fade",
              if (state.activeTab == "paxloads") {
                heatmapOfPaxloads(props.terminalName)
              } else ""),
            <.div(^.id := "waits", ^.className := "tab-pane fade",
              if (state.activeTab == "waits") {
                heatmapOfWaittimes(props.terminalName, props.simulationResults)
              } else "")
          ))
      }))
    .configure(Reusability.shouldComponentUpdate)
    .build

  def apply(props: Props): VdomElement = component(props)
}

object TerminalContentComponent {

  case class Props(
                    crunchStatePot: Pot[CrunchState],
                    airportConfig: AirportConfig,
                    terminalName: TerminalName,
                    airportInfoPot: Pot[AirportInfo],
                    simulationResult: Map[QueueName, QueueSimulationResult],
                    crunchResult: Map[QueueName, CrunchResult],
                    deployments: QueueStaffDeployments,
                    workloads: Workloads,
                    actualDesks: Map[QueueName, Map[Long, DeskStat]],
                    timeRangeHours: TimeRangeHours,
                    dayToDisplay: SDateLike
                  ) {
    lazy val hash = {
      val depsHash: List[Option[List[Int]]] = deployments.values.map(drtsPot => {
        drtsPot.toOption.map(drts => {
          drts.items.map(drt => {
            drt.hashCode
          }).toList
        })
      }).toList

      val flightsHash: Option[List[(Int, String, String, String, String, String, String, String, String, Long, Int)]] = crunchStatePot.toOption.map(_.flights.toList.map(f => {
        (f.splits.hashCode,
          f.apiFlight.Status,
          f.apiFlight.Gate,
          f.apiFlight.Stand,
          f.apiFlight.SchDT,
          f.apiFlight.EstDT,
          f.apiFlight.ActDT,
          f.apiFlight.EstChoxDT,
          f.apiFlight.ActChoxDT,
          f.apiFlight.PcpTime,
          f.apiFlight.ActPax
        )
      }))

      (depsHash, flightsHash, timeRangeHours.start, timeRangeHours.end)
    }
  }

  def filterFlightsByRange(date: SDateLike, range: TimeRangeHours, arrivals: List[ApiFlightWithSplits]) = arrivals.filter(a => {

    def withinRange(ds: String) = if (ds.length > 0) SDate.parse(ds) match {
      case s: SDateLike if s.ddMMyyString == date.ddMMyyString =>
        s.getHours >= range.start && s.getHours < range.end
      case _ => false
    } else false

    withinRange(a.apiFlight.SchDT) || withinRange(a.apiFlight.EstDT) || withinRange(a.apiFlight.ActDT) || withinRange(a.apiFlight.EstChoxDT) || withinRange(a.apiFlight.ActChoxDT) || withinRange(SDate(MilliDate(a.apiFlight.PcpTime)).toISOString)
  })

  val timelineComp: Option[(Arrival) => html_<^.VdomElement] = Some(FlightTableComponents.timelineCompFunc _)

  def airportWrapper(portCode: String) = SPACircuit.connect(_.airportInfos.getOrElse(portCode, Pending()))

  def originMapper(portCode: String): VdomElement = {
    Try {
      vdomElementFromComponent(airportWrapper(portCode) { (proxy: ModelProxy[Pot[AirportInfo]]) =>
        <.span(
          proxy().render(ai => <.span(^.title := s"${ai.airportName}, ${ai.city}, ${ai.country}", portCode)),
          proxy().renderEmpty(<.span(portCode)),
          proxy().renderPending((n) => <.span(portCode)))
      })
    }.recover {
      case e =>
        log.error(s"origin mapper error $e")
        vdomElementFromTag(<.div(portCode))
    }.get
  }

  case class State(activeTab: String)

  class Backend(t: BackendScope[Props, State]) {
    val arrivalsTableComponent = FlightsWithSplitsTable.ArrivalsTable(
      timelineComp,
      originMapper,
      splitsGraphComponentColoured)(paxComp(843))

    def render(props: Props, state: State) = {
      val bestPax = ArrivalHelper.bestPax _
      val queueOrder = props.airportConfig.queueOrder

      <.div(
        <.ul(^.className := "nav nav-tabs",
          <.li(^.className := "active", <.a(VdomAttr("data-toggle") := "tab", ^.href := "#arrivals", "Arrivals"), ^.onClick --> t.modState(_ => State("arrivals"))),
          <.li(<.a(VdomAttr("data-toggle") := "tab", ^.href := "#queues", "Desks & Queues Old"), ^.onClick --> t.modState(_ => State("queues"))),
          <.li(<.a(VdomAttr("data-toggle") := "tab", ^.href := "#desksAndQueues", "Desks & Queues"), ^.onClick --> t.modState(_ => State("desksAndQueues"))),
          <.li(<.a(VdomAttr("data-toggle") := "tab", ^.href := "#staffing", "Staffing"), ^.onClick --> t.modState(_ => State("staffing")))
        ),
        <.div(^.className := "tab-content",
          <.div(^.id := "arrivals", ^.className := "tab-pane fade in active", {
            if (state.activeTab == "arrivals") {

              <.div(props.crunchStatePot.renderReady((crunchState: CrunchState) => {
                val flightsWithSplits = crunchState.flights
                val terminalFlights = flightsWithSplits.filter(f => f.apiFlight.Terminal == props.terminalName)
                val flightsInRange = filterFlightsByRange(props.dayToDisplay, props.timeRangeHours, terminalFlights.toList)

                arrivalsTableComponent(FlightsWithSplitsTable.Props(flightsInRange, bestPax, queueOrder))
              }))
            } else ""
          }),
          <.div(^.id := "queues", ^.className := "tab-pane fade terminal-desk-recs-container",
            if (state.activeTab == "queues") {
              val deploymentProps = TerminalDeploymentsTable.TerminalProps(
                props.airportConfig,
                props.terminalName,
                props.crunchStatePot,
                props.simulationResult,
                props.crunchResult,
                props.deployments,
                props.workloads,
                props.actualDesks,
                props.timeRangeHours
              )
              TerminalDeploymentsTable.terminalDeploymentsComponent(deploymentProps)
            } else ""
          ),
          <.div(^.id := "desksAndQueues", ^.className := "tab-pane fade terminal-desk-recs-container",
            if (state.activeTab == "desksAndQueues") {
              props.crunchStatePot.renderReady( crunchState => {

                TerminalDesksAndQueues(TerminalDesksAndQueues.Props(crunchState, props.airportConfig, props.terminalName))
              })
            } else ""
          ),
          <.div(^.id := "staffing", ^.className := "tab-pane fade terminal-staffing-container",
            if (state.activeTab == "staffing") {
              TerminalStaffing(TerminalStaffing.Props(props.terminalName))
            } else ""
          )))

    }
  }

  implicit val propsReuse = Reusability.by((_: Props).hash)
  implicit val stateReuse = Reusability.caseClass[State]

  val component = ScalaComponent.builder[Props]("TerminalContentComponent")
    .initialState(State("arrivals"))
    .renderBackend[TerminalContentComponent.Backend]
    .componentDidMount((p) => {
      Callback.log(s"terminal component didMount")
    })
    .configure(Reusability.shouldComponentUpdate)
    .build

  def apply(props: Props): VdomElement = {
    component(props)
  }
}
