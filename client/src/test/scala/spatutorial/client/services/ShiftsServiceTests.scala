package spatutorial.client.services

import spatutorial.client.services.JSDateConversions.SDate
import spatutorial.shared.{MilliDate, WorkloadsHelpers}
import utest._

import scala.scalajs.js.Date

object ShiftsServiceTests extends TestSuite {

  import spatutorial.client.services.JSDateConversions._

  def tests = TestSuite {
    'StaffShifts - {
      "As an HO, either in planning or at start of shift, " +
        "I want to be able tell DRT about staff available by shift for a given period" +
        "So that I can easily get an initial state for the system" - {

        "some implicits make things nicer whether we're server side or client side " - {
          val startDt = MilliDate(SDate(2016, 12, 10, 10, 0))
          val endDate = MilliDate(SDate(2016, 12, 19, 12, 0))
          val shifts = Shift("alpha", startDt, endDate, 10)

          assert(shifts == Shift("alpha", 1484042400000L, 1484827200000L, 10))
        }

        "Given a shift of 10 people, if we ask how many staff are available" - {
          val shifts = Shift("alpha", SDate(2016, 12, 10, 10, 0), SDate(2016, 12, 10, 19, 0), 10)
          val shiftService = ShiftService(shifts :: Nil)
          "at its first bound, then we get 10" - {
            assert(shiftService.staffAt(SDate(2016, 12, 10, 10, 0)) == 10)
          }
          "at its upper bound, then we get 10" - {
            assert(shiftService.staffAt(SDate(2016, 12, 10, 19, 0)) == 10)
          }
          "can compare dates" - {
            assert(MilliDate(SDate(2015, 10, 10, 10, 10)) < MilliDate(SDate(2016, 12, 12, 12, 12)))
            assert(MilliDate(SDate(2015, 10, 10, 10, 10)) <= MilliDate(SDate(2016, 12, 12, 12, 12)))
          }


          //          "before its lower bound, then we get 0" - {
          //            val actualStaff: Int = shiftService.staffAt(SDate(2015, 10, 10, 10, 10))
          //            assert(actualStaff == 0)
          //          }
        }
        "Given two overlapping shifts" - {
          val shifts = Shift("alpha", SDate(2016, 12, 10, 10, 0), SDate(2016, 12, 10, 19, 0), 10) ::
            Shift("beta", SDate(2016, 12, 10, 18, 0), SDate(2016, 12, 10, 23, 0), 5) :: Nil
          val shiftService = ShiftService(shifts)
          "on the overlap the staff is the sum of both" - {
            assert(shiftService.staffAt(SDate(2016, 12, 10, 18, 30)) == 15)
          }
          "on the lower bound of the second shift the staff is the sum of both (15)" - {
            assert(shiftService.staffAt(SDate(2016, 12, 10, 18, 0)) == 15)
          }
          "on the upper bound of the second shift the staff the number of the second shift (5)" - {
            assert(shiftService.staffAt(SDate(2016, 12, 10, 23, 0)) == 5)
          }
          "after the upper bound of the second shift the staff is 0" - {
            assert(shiftService.staffAt(SDate(2016, 12, 10, 23, 1)) == 0)
          }
          "before the lower bound of the first shift the staff is 0" - {
            assert(shiftService.staffAt(SDate(2016, 12, 10, 9, 59)) == 0)
          }
        }

        "Given all the shifts, how fast is it?" - {
          val shiftsRawTsv =
            """
              |Alpha 1 ODM	01/12/16	06:30	15:18
              |Alpha 1with ODM	01/12/16	06:30	15:18
              |Alpha 2 /Customs from 0845
              |"Alpha + Immigration, Assurance"	01/12/16	08:00	16:48
              |"Alpha + Immigration, Assurance"	01/12/16	08:00	16:48
              |
              |0700-1100	01/12/16	07:00	11:00
              |0700-1100	01/12/16	07:00	11:00
              |0700-1100	01/12/16	07:00	11:00
              |0700-1100	01/12/16	07:00	11:00
              |0700-1100	01/12/16	07:00	11:00
              |0700-1100	01/12/16	07:00	11:00
              |0700-1400	01/12/16	07:00	14:00
              |0700-1400	01/12/16	07:00	14:00
              |0700-1600	01/12/16	07:00	16:00
              |0700-1600	01/12/16	07:00	16:00
              |0800-1700	01/12/16	08:00	17:00
              |0800-1700	01/12/16	08:00	17:00
              |
              |Alpha/FGY	01/12/16	06:00	14:48
              |Alpha/Casework	01/12/16	07:00	14:24
              |Alpha (D)	01/12/16	07:00	14:54
              |Alpha (DETECTION)	01/12/16	07:00	15:48
              |Alpha (D)	01/12/16	07:00	15:48
              |Alpha/SEA	01/12/16	07:00	15:48
              |Alpha	01/12/16	07:00	15:48
              |Alpha from 0845 with Crime Team/SB	01/12/16	07:00	15:48
              |Alpha	01/12/16	07:00	15:48
              |Alpha	01/12/16	07:00	15:48
              |Alpha - R	01/12/16	07:00	15:48
              |Alpha/OSO/SAT	01/12/16	07:00	15:48
              |Alpha from 0845 with Crime Team/SB	01/12/16	07:00	15:48
              |Alpha	01/12/16	07:00	15:48
              |Alpha (DETECTION)	01/12/16	07:00	17:00
              |
              |Training	01/12/16	08:00	17:24
              |Stats	01/12/16	09:00	16:24
              |WI	01/12/16	09:30	14:30
              |09:30-16:54	01/12/16	09:30	16:54
              |1030-1915	01/12/16	10:30	19:15
              |Bravo	01/12/16	11:00	18:24
              |Bravo	01/12/16	11:00	18:54
              |Bravo 1430-1700 CT training	01/12/16	11:00	19:48
              |Bravo - R	01/12/16	11:00	19:48
              |1200-2000	01/12/16	12:00	20:00
              |
              |Late Duty SO
              |Charlie - ODM	01/12/16	14:30	23:18
              |Charlie/SEA with OTO Joanne Clark	01/12/16	14:30	23:18
              |Charlie/SEA/SAT OTO for Alison Burbeary	01/12/16	14:30	23:18
              |Charlie	01/12/16	14:30	23:18
              |Charlie 1430-1700 CT Training (D)	01/12/16	14:30	23:18
              |Charlie - R	01/12/16	14:30	23:18
              |Charlie/SEA	01/12/16	14:30	23:18
              |
              |Delta/OSO (D)	01/12/16	16:00	00:48
              |Delta - R	01/12/16	16:00	00:48
              |Delta/Fgy	01/12/16	16:00	00:48
              |Delta/SEA with OTO M Elmhassani	01/12/16	16:00	00:48
              |Delta	01/12/16	16:00	00:48
              |Delta	01/12/16	16:00	00:48
              |Delta/CWK	01/12/16	16:00	00:48
              |Delta/SEA	01/12/16	16:00	00:48
              |1600-2000	01/12/16	16:00	20:00
              |1600-2000	01/12/16	16:00	20:00
              |"Delta 1 Immigration, Assurance"	01/12/16	16:36	01:24
              |
              |Echo/SEA OTO for K Hopkins	01/12/16	17:00	01:48
              |Echo	01/12/16	17:00	01:48
              |
              |1800-0100	01/12/16	18:00	01:00
              |1800-0100	01/12/16	18:00	01:00
              |1800-0100	01/12/16	18:00	01:00
              |1800-0100	01/12/16	18:00	01:00
              |1800-0100	01/12/16	18:00	01:00
              |1800-0100	01/12/16	18:00	01:00
              |1800-2200	01/12/16	18:00	22:00
              |
              |Night	01/12/16	22:00	08:00
              |Night - ODM	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
              |Night	01/12/16	22:30	07:18
            """.stripMargin

          val lines = shiftsRawTsv.split("\n")
          val parsedShifts = lines.map(l => l.split("\t"))
            .filter(_.length == 4)
            .map(pl => Shift(pl(0), pl(1), pl(2), pl(3)))


          println(parsedShifts.mkString("\n"))

//
//          "asking for a whole days shape with individual stuff" - {
//            val shiftService = ShiftService(parsedShifts.toList)
//            val startOfDay: Long = SDate(2016, 12, 1, 0, 0)
//            val timeMinPlusOneDay: Long = startOfDay + WorkloadsHelpers.oneMinute * 60 * 36
//            val daysWorthOf15Minutes = startOfDay until timeMinPlusOneDay by (WorkloadsHelpers.oneMinute * 15)
//
//            TestTimer.timeIt("individuals")(50) {
//              val staffAtTIme = daysWorthOf15Minutes.map {
//                time => (time) -> shiftService.staffAt(time)
//              }
//            }
//
//          }

//          "asking for a whole days shape with grouped staff" - {
//            val shiftService = ShiftService(ShiftService.groupPeopleByShiftTimes(parsedShifts).toList)
//            val startOfDay: Long = SDate(2016, 12, 1, 0, 0)
//            val timeMinPlusOneDay: Long = startOfDay + WorkloadsHelpers.oneMinute * 60 * 36
//            val daysWorthOf15Minutes = startOfDay until timeMinPlusOneDay by (WorkloadsHelpers.oneMinute * 15)
//
//            TestTimer.timeIt("grouped")(50) {
//              val staffAtTIme = daysWorthOf15Minutes.map {
//                time => (time) -> shiftService.staffAt(time)
//              }
//            }
//          }
//
//
          "asking for a whole days shape with movements of grouped staff" - {
            val shiftService = MovementsShiftService(ShiftService.groupPeopleByShiftTimes(parsedShifts.toList).toList)
            val startOfDay: Long = SDate(2016, 12, 1, 0, 0)
            val timeMinPlusOneDay: Long = startOfDay + WorkloadsHelpers.oneMinute * 60 * 36
            val daysWorthOf15Minutes = startOfDay until timeMinPlusOneDay by (WorkloadsHelpers.oneMinute * 15)

            TestTimer.timeIt("movements")(1000) {
              val staffAtTIme = daysWorthOf15Minutes.map {
                time => (time) -> shiftService.staffAt(time)
              }
            }

          }

          "Staff movements" - {
            import StaffMovements._
            val shiftService = ShiftService(parsedShifts.toList)
            val movements = (StaffMovement("IS81", SDate(2016, 12, 10, 10, 0), -2) :: Nil).sortBy(_.time)

            "Shifts can be represented as staff movements" - {
              val sDate: MilliDate = SDate(2016, 12, 10, 10, 0)
              assert(staffAt(shiftService)(movements)(sDate) == shiftService.staffAt(sDate) - 2)
            }
            "Movements from after the asked for date are not included" - {
              val sDate: MilliDate = SDate(2016, 12, 10, 9, 0)
              assert(staffAt(shiftService)(movements)(sDate) == shiftService.staffAt(sDate))
            }
          }
        }
      }
    }
  }
}
object TestTimer {
  def timeIt(name: String)(times: Int)(f:  => Unit) = {
    val start = new Date()
    println(s"${name}: Starting timer at ${start}")
    (1 to times).foreach(n => {
      println(n)
      f
    })
    val end = new Date()
    println(s"${name} Trial done at ${end}")
    val timeTaken = (end.getTime() - start.getTime())
    println(s"${name} Time taken in ${times} runs ${timeTaken}ms, ${timeTaken.toDouble/times} per run")
  }
}