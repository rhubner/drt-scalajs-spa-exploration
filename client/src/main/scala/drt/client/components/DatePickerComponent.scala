package drt.client.components

import drt.client.SPAMain.{Loc, TerminalPageTabLoc}
import drt.client.actions.Actions.SetViewMode
import drt.client.logger.{Logger, LoggerFactory}
import drt.client.services.JSDateConversions.SDate
import drt.client.services._
import drt.shared.SDateLike
import japgolly.scalajs.react.extra.Reusability
import japgolly.scalajs.react.extra.router.RouterCtl
import japgolly.scalajs.react.vdom.html_<^._
import japgolly.scalajs.react.{ReactEventFromInput, ScalaComponent}

import scala.scalajs.js.Date

object DatePickerComponent {
  val log: Logger = LoggerFactory.getLogger(getClass.getName)

  case class Props(router: RouterCtl[Loc], terminalPageTab: TerminalPageTabLoc)

  case class State(showDatePicker: Boolean, day: Int, month: Int, year: Int, hours: Int, minutes: Int) {
    def selectedDateTime = SDate(year, month, day, hours, minutes)
  }

  val today = SDate.now()

  def formRow(label: String, xs: TagMod*) = {
    <.div(^.className := "form-group row",
      <.label(label, ^.className := "col-sm-1 col-form-label"),
      <.div(^.className := "col-sm-8", xs.toTagMod))
  }

  implicit val propsReuse: Reusability[Props] = Reusability.by(_.terminalPageTab.viewMode.hashCode())
  implicit val stateReuse: Reusability[State] = Reusability.caseClass[State]

  val component = ScalaComponent.builder[Props]("DatePicker")
    .initialStateFromProps(
      p => {
        log.info(s"Setting state from $p")
        val viewMode = p.terminalPageTab.viewMode
        val time = viewMode.time
        val initState = State(false, time.getDate(), time.getMonth(), time.getFullYear(), time.getHours(), time.getMinutes())
        SPACircuit.dispatch(SetViewMode(viewMode))
        log.info(s"initial state from props: $initState")
        initState
      }
    )
    .renderPS((scope, props, state) => {
      val months = Seq("January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December").zip(1 to 12)
      val days = Seq.range(1, 31)
      val years = Seq.range(2017, today.getFullYear() + 1)

      def drawSelect(names: Seq[String], values: Seq[String], defaultValue: Int, callback: (String) => (State) => State) = {
        <.select(^.className := "form-control", ^.value := defaultValue.toString,
          ^.onChange ==> ((e: ReactEventFromInput) => scope.modState(callback(e.target.value))),
          values.zip(names).map {
            case (name, value) => <.option(^.value := value, name)
          }.toTagMod)
      }

      def daysInMonth(month: Int, year: Int) = new Date(year, month, 0).getDate()

      def updateUrlWithDate(date: Option[SDateLike]) = {
        props.router.set(props.terminalPageTab.copy(date = date.map(_.toLocalDateTimeString()))).runNow()
      }

      def selectPointInTime = (e: ReactEventFromInput) => {
        updateUrlWithDate(Option(state.selectedDateTime))
        scope.modState(_.copy(showDatePicker = false))
      }

      def selectYesterday = (e: ReactEventFromInput) => {
        val yesterday = SDate.midnightThisMorning().addMinutes(-1)
        updateUrlWithDate(Option(yesterday))
        scope.modState(_.copy(true, yesterday.getDate(), yesterday.getMonth(), yesterday.getFullYear(), yesterday.getHours(), yesterday.getMinutes()))
      }

      def selectTomorrow = (e: ReactEventFromInput) => {
        val tomorrow = SDate.midnightThisMorning().addDays(2).addMinutes(-1)
        updateUrlWithDate(Option(tomorrow))
        scope.modState(_.copy(true, tomorrow.getDate(), tomorrow.getMonth(), tomorrow.getFullYear(), tomorrow.getHours(), tomorrow.getMinutes()))
      }

      def selectToday = (e: ReactEventFromInput) => {
        val now = SDate.now()
        updateUrlWithDate(None)
        scope.modState(_.copy(true, now.getDate(), now.getMonth(), now.getFullYear(), now.getHours(), now.getMinutes()))
      }

      val yesterdayActive = if (state.selectedDateTime.ddMMyyString == SDate.now().addDays(-1).ddMMyyString) "active" else ""
      val todayActive = if (state.selectedDateTime.ddMMyyString == SDate.now().ddMMyyString) "active" else ""
      val tomorrowActive = if (state.selectedDateTime.ddMMyyString == SDate.now().addDays(1).ddMMyyString) "active" else ""

      val errorMessage = if (!SnapshotSelector.isLaterThanEarliest(state.selectedDateTime)) <.div(^.className := "error-message", s"Earliest available is ${SnapshotSelector.earliestAvailable.ddMMyyString}") else <.div()

      def isDataAvailableForDate = SnapshotSelector.isLaterThanEarliest(state.selectedDateTime)

      <.div(^.className := "date-selector",
        <.div(^.className := "form-group row",
          <.div(^.className := "btn-group col-sm-4 no-gutters", VdomAttr("data-toggle") := "buttons",
            <.div(^.className := s"btn btn-primary $yesterdayActive", "Yesterday", ^.onClick ==> selectYesterday),
            <.div(^.className := s"btn btn-primary $todayActive", "Today", ^.onClick ==> selectToday),
            <.div(^.className := s"btn btn-primary $tomorrowActive", "Tomorrow", ^.onClick ==> selectTomorrow)),
          <.div(
            <.label(^.className := "col-sm-1 no-gutters text-center", "or"),
            List(
              <.div(^.className := "col-sm-1 no-gutters", drawSelect(names = List.range(1, daysInMonth(state.month, state.year) + 1).map(_.toString), values = days.map(_.toString), defaultValue = state.day, callback = (v: String) => (s: State) => s.copy(day = v.toInt))),
              <.div(^.className := "col-sm-2 no-gutters", drawSelect(names = months.map(_._2.toString), values = months.map(_._1.toString), defaultValue = state.month, callback = (v: String) => (s: State) => s.copy(month = v.toInt))),
              <.div(^.className := "col-sm-1 no-gutters", drawSelect(names = years.map(_.toString), values = years.map(_.toString), defaultValue = state.year, callback = (v: String) => (s: State) => s.copy(year = v.toInt))),
              <.input.button(^.value := "Go", ^.className := "btn btn-primary", ^.onClick ==> selectPointInTime, ^.disabled := !isDataAvailableForDate),
              errorMessage
            ).toTagMod))
      )
    })
    .configure(Reusability.shouldComponentUpdate)
    .build

  def apply(props: Props): VdomElement = component(props)
}
