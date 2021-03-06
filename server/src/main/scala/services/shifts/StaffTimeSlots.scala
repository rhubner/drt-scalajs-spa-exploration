package services.shifts

import drt.shared.{SDateLike, StaffTimeSlotsForTerminalMonth}
import services.SDate

import scala.util.{Success, Try}

object StaffTimeSlots {

  def slotsToShifts(slots: StaffTimeSlotsForTerminalMonth) = {
    val monthSDate = SDate(slots.monthMillis)
    slots.timeSlots.filter(_.staff != 0).zipWithIndex.map {
      case (slot, index) =>
        val dateTime = SDate(slot.start)
        f"shift${monthSDate.getMonth()}%02d${monthSDate.getFullYear()}$index, ${slot.terminal}, ${dateTime.ddMMyyString}, ${dateTime.prettyTime}, ${dateTime.addMillis(slot.durationMillis - 1).prettyTime}, ${slot.staff}"
    }.mkString("\n")
  }

  def removeMonthFromShifts(shifts: String, date: SDateLike) = {
    val twoDigitYear = date.getFullYear().toString.substring(2, 4)
    val filterDate2DigitYear = f"${date.getDate()}%02d/${date.getMonth()}%02d/$twoDigitYear"
    val filterDate4DigitYear = f"${date.getDate()}%02d/${date.getMonth()}%02d/${date.getFullYear()}"
    val todaysShifts = shiftsToLines(shifts).filter(l => {
      l.contains(filterDate2DigitYear) || l.contains(filterDate4DigitYear)
    })
  }

  def isDateInMonth(dateString: String, month: SDateLike) = {
    val ymd = dateString.split("/").toList

    Try((ymd(0).toInt, ymd(1).toInt, ymd(2).toInt)) match {
      case Success((d, m, y)) if month.getMonth == m && month.getFullYear() == y =>
        true
      case Success((d, m, y)) if month.getMonth == m && month.getFullYear() - 2000 == y =>
        true
      case other =>
        false
    }
  }

  def replaceShiftMonthWithTimeSlotsForMonth(existingShifts: String, slots: StaffTimeSlotsForTerminalMonth) = {
    val shiftsExcludingNewMonth = shiftsToLines(existingShifts)
      .filter(line => {
        shiftLineToFieldList(line) match {
          case List(_, t, d, _, _, _) if !isDateInMonth(d, SDate(slots.monthMillis)) || t != slots.terminal => true
          case _ => false
        }
      })

    (shiftsExcludingNewMonth.mkString("\n") + "\n" + StaffTimeSlots.slotsToShifts(slots)).trim
  }

  private def shiftLineToFieldList(line: String) = {
    line.replaceAll("([^\\\\]),", "$1\",\"")
      .split("\",\"").toList.map(_.trim)
  }

  private def shiftsToLines(existingShifts: String) = {
    existingShifts.split("\n")
  }

  def getShiftsForMonth(shifts: String, month: SDateLike) = {
    shiftsToLines(shifts).filter(line => {
      shiftLineToFieldList(line) match {
        case List(_, _, d, _, _, _) =>
          isDateInMonth(d, month)
        case _ => false
      }
    }).mkString("\n")
  }
}
