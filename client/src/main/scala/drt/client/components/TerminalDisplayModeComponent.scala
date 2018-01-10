package drt.client.components

import diode.data.Pot
import drt.client.SPAMain.{Loc, TerminalPageTabLoc}
import drt.client.services.JSDateConversions.SDate
import drt.client.services._
import drt.shared.CrunchApi.{CrunchState, ForecastPeriodWithHeadlines}
import drt.shared.{AirportConfig, AirportInfo, MonthOfRawShifts, StaffMovement}
import japgolly.scalajs.react.ScalaComponent
import japgolly.scalajs.react.extra.router.RouterCtl
import japgolly.scalajs.react.vdom.html_<^.{<, ^, _}

import scala.collection.immutable

object TerminalDisplayModeComponent {

  case class Props(crunchStatePot: Pot[CrunchState],
                   forecastPeriodPot: Pot[ForecastPeriodWithHeadlines],
                   potShifts: Pot[String],
                   potMonthOfShifts: Pot[MonthOfRawShifts],
                   potFixedPoints: Pot[String],
                   potStaffMovements: Pot[immutable.Seq[StaffMovement]],
                   airportConfig: AirportConfig,
                   terminalPageTab: TerminalPageTabLoc,
                   airportInfoPot: Pot[AirportInfo],
                   timeRangeHours: TimeRangeHours,
                   router: RouterCtl[Loc],
                   loadingState: LoadingState,
                   showActuals: Boolean
                  )

  case class State(activeTab: String)

  val component = ScalaComponent.builder[Props]("Terminal")
    .initialStateFromProps(p => State(p.terminalPageTab.mode))
    .render_PS((props, state) => {

      val terminalContentProps = TerminalContentComponent.Props(
        props.crunchStatePot,
        props.potShifts,
        props.potFixedPoints,
        props.potStaffMovements,
        props.airportConfig,
        props.terminalPageTab,
        props.airportInfoPot,
        props.timeRangeHours,
        props.router,
        props.showActuals
      )

      val currentClass = if (state.activeTab == "current") "active" else ""
      val snapshotDataClass = if (state.activeTab == "snapshot") "active" else ""
      val planningClass = if (state.activeTab == "planning") "active" else ""
      val staffingClass = if (state.activeTab == "staffing") "active" else ""

      val currentContentClass = if (state.activeTab == "current") "fade in active" else "fade out"
      val snapshotContentClass = if (state.activeTab == "snapshot") "fade in active" else "fade out"
      val planningContentClass = if (state.activeTab == "planning") "fade in active" else "fade out"
      val staffingContentClass = if (state.activeTab == "staffing") "fade in active" else "fade out"

      val subMode = if (props.terminalPageTab.mode == "staffing") "desksAndQueues" else props.terminalPageTab.subMode

      <.div(
        <.ul(^.className := "nav nav-tabs",
          <.li(^.className := currentClass, <.a(VdomAttr("data-toggle") := "subMode", "Current"), ^.onClick --> {
            props.router.set(props.terminalPageTab.copy(mode = "current", subMode = subMode, date = None))
          }),
          <.li(^.className := snapshotDataClass,
            <.a(VdomAttr("data-toggle") := "subMode", "Snapshot"), ^.onClick --> {
              props.router.set(props.terminalPageTab.copy(mode = "snapshot", subMode = subMode, date = None))
            }
          ),
          <.li(^.className := planningClass,
            <.a(VdomAttr("data-toggle") := "subMode", "Planning"), ^.onClick --> {
              props.router.set(props.terminalPageTab.copy(mode = "planning", subMode = subMode, date = None))
            }
          ),
          <.li(^.className := staffingClass,
            <.a(VdomAttr("data-toggle") := "subMode", "Staffing"), ^.onClick --> {
              props.router.set(props.terminalPageTab.copy(mode = "staffing", subMode = "60", date = None))
            }
          )
        ),
        <.div(^.className := "subMode-content",
          <.div(^.id := "current", ^.className := s"subMode-pane $currentContentClass", {
            if (state.activeTab == "current") <.div(
              <.h2(props.terminalPageTab.date match {
                case Some(ds) if SDate(ds).ddMMyyString == SDate.now().ddMMyyString => "Live View"
                case Some(ds) if SDate(ds).millisSinceEpoch < SDate.now().millisSinceEpoch => "Historic View"
                case Some(ds) if SDate(ds).millisSinceEpoch > SDate.now().millisSinceEpoch => "Forecast View"
                case _ => "Live View"
              }),
              DatePickerComponent(DatePickerComponent.Props(props.router, props.terminalPageTab, props.timeRangeHours, props.loadingState)),
              TerminalContentComponent(terminalContentProps)
            ) else ""
          }),
          <.div(^.id := "snapshot", ^.className := s"subMode-pane $snapshotContentClass", {
            if (state.activeTab == "snapshot") <.div(
              <.h2("Snapshot View"),
              SnapshotSelector(props.router, props.terminalPageTab, props.timeRangeHours, props.loadingState),
              TerminalContentComponent(terminalContentProps)
            ) else ""
          }),
          <.div(^.id := "planning", ^.className := s"subMode-pane $planningContentClass", {
            if (state.activeTab == "planning") {
              <.div(
                <.div(props.forecastPeriodPot.render(fp => {
                  TerminalPlanningComponent(TerminalPlanningComponent.Props(fp, props.terminalPageTab, props.router))
                }))
              )
            } else ""
          }),
          <.div(^.id := "staffing", ^.className := s"subMode-pane terminal-staffing-container $staffingContentClass",
            if (state.activeTab == "staffing") {
              props.potMonthOfShifts.render(ms => {
                TerminalStaffingV2(ms.shifts, props.terminalPageTab, props.router)
              })
            } else ""
          )
        )
      )
    })
    .build

  def apply(props: Props): VdomElement = component(props)
}


