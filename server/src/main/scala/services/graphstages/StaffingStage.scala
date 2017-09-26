package services.graphstages

import java.util.UUID

import akka.stream._
import akka.stream.stage.{GraphStage, GraphStageLogic, InHandler, OutHandler}
import drt.shared.FlightsApi.{QueueName, TerminalName}
import drt.shared.{MilliDate, SDateLike, Simulations, StaffMovement}
import org.slf4j.LoggerFactory
import services.graphstages.Crunch.{CrunchMinute, CrunchState, desksForHourOfDayInUKLocalTime}
import services.graphstages.StaffDeploymentCalculator.{addDeployments, queueRecsToDeployments}
import services.workloadcalculator.PaxLoadCalculator.MillisSinceEpoch
import services.{OptimizerConfig, SDate, TryRenjin}

import scala.concurrent.{Await, Future}
import scala.concurrent.duration._
import scala.util.{Failure, Success, Try}
import scala.concurrent.ExecutionContext.Implicits.global
import scala.language.postfixOps

class StaffingStage(initialCrunchStateFuture: Future[Option[CrunchState]], minMaxDesks: Map[TerminalName, Map[QueueName, (List[Int], List[Int])]], slaByQueue: Map[QueueName, Int])
  extends GraphStage[FanInShape4[CrunchState, String, String, Seq[StaffMovement], CrunchState]] {
  val inCrunch: Inlet[CrunchState] = Inlet[CrunchState]("CrunchStateWithoutSimulations.in")
  val inShifts: Inlet[String] = Inlet[String]("Shifts.in")
  val inFixedPoints: Inlet[String] = Inlet[String]("FixedPoints.in")
  val inMovements: Inlet[Seq[StaffMovement]] = Inlet[Seq[StaffMovement]]("Movements.in")
  val outCrunch: Outlet[CrunchState] = Outlet[CrunchState]("CrunchStateWithSimulations.out")

  val allInlets = List(inCrunch, inShifts, inFixedPoints, inMovements)

  var crunchStateOption: Option[CrunchState] = None
  var shifts: Option[String] = None
  var fixedPoints: Option[String] = None
  var movements: Option[Seq[StaffMovement]] = None

  var crunchStateWithSimulation: Option[CrunchState] = None

  val log = LoggerFactory.getLogger(getClass)

  override def shape: FanInShape4[CrunchState, String, String, Seq[StaffMovement], CrunchState] =
    new FanInShape4(inCrunch, inShifts, inFixedPoints, inMovements, outCrunch)

  override def createLogic(inheritedAttributes: Attributes): GraphStageLogic = {
    new GraphStageLogic(shape) {
      override def preStart(): Unit = {
        initialCrunchStateFuture.onSuccess {
          case initialCrunchStateOption =>
            log.info(s"Received initial crunchState")
            crunchStateOption = initialCrunchStateOption
        }
        Await.ready(initialCrunchStateFuture, 10 seconds)

        super.preStart()
      }

      setHandler(inCrunch, new InHandler {
        override def onPush(): Unit = {
          log.info(s"inCrunch onPush() - setting crunchStateOption")
          crunchStateOption = Option(grab(inCrunch))
          runSimulationAndPush()
        }
      })

      setHandler(inShifts, new InHandler {
        override def onPush(): Unit = {
          log.info(s"inShifts onPush() - setting shifts")
          shifts = Option(grab(inShifts))
          runSimulationAndPush()
        }
      })

      setHandler(inFixedPoints, new InHandler {
        override def onPush(): Unit = {
          log.info(s"inFixedPoints onPush() - setting fixedPoints")
          fixedPoints = Option(grab(inFixedPoints))
          runSimulationAndPush()
        }
      })

      setHandler(inMovements, new InHandler {
        override def onPush(): Unit = {
          log.info(s"inMovements onPush() - setting movements")
          movements = Option(grab(inMovements))
          runSimulationAndPush()
        }
      })

      def pushAndPull() = {
        crunchStateWithSimulation match {
          case None =>
            log.info(s"Nothing to push")
          case Some(cs) =>
            log.info(s"Pushing CrunchStateWithSimulation")
            push(outCrunch, cs)
            crunchStateWithSimulation = None
        }

        allInlets.foreach(inlet => if (!hasBeenPulled(inlet)) pull(inlet))
      }

      def runSimulationAndPush() = {
        log.info(s"Running simulation")

        crunchStateWithSimulation = crunchStateOption.map {
          case cs@ CrunchState(_, _, _, crunchMinutes) =>
            val crunchMinutesWithDeployments = addDeployments(crunchMinutes, queueRecsToDeployments(_.toInt), staffDeploymentsByTerminalAndQueue, minMaxDesks)
            val crunchMinutesWithSimulation = crunchMinutesWithDeployments.groupBy(_.terminalName).flatMap {
              case (tn, tcms) =>
                val minutes = tcms.groupBy(_.queueName).flatMap {
                  case (qn, qcms) =>
                    val minWlSd = qcms.toSeq.map(cm => Tuple3(cm.minute, cm.workLoad, cm.deployedDesks)).sortBy(_._1)
                    val workLoads = minWlSd.map { case (_, wl, _) => wl }.toList
                    val deployedDesks = minWlSd.map { case (_, _, sd) => sd.getOrElse(0) }.toList
                    val config = OptimizerConfig(slaByQueue(qn))
                    val queueSimResult: Simulations.QueueSimulationResult = TryRenjin.runSimulationOfWork(workLoads, deployedDesks, config)
                    val simWaits = queueSimResult.waitTimes
                    qcms.toSeq.sortBy(_.minute).zipWithIndex.map {
                      case (cm, idx) => cm.copy(deployedWait = Option(simWaits(idx)))
                    }.toSet
                }
                minutes
            }.toSet
            cs.copy(crunchMinutes = crunchMinutesWithSimulation)
        }

        if (isAvailable(outCrunch)) pushAndPull()
      }

      val staffDeploymentsByTerminalAndQueue: (MillisSinceEpoch, TerminalName) => Int = {
        val rawShiftsString = shifts.getOrElse("")
        val rawFixedPointsString = fixedPoints.getOrElse("")
        val myMovements = movements.getOrElse(Seq())

        val myShifts = StaffAssignmentParser(rawShiftsString).parsedAssignments.toList
        val myFixedPoints = StaffAssignmentParser(rawFixedPointsString).parsedAssignments.toList

        if (myShifts.exists(s => s.isFailure) || myFixedPoints.exists(s => s.isFailure)) {
          (_: MillisSinceEpoch, _: TerminalName) => 0
        } else {
          val successfulShifts = myShifts.collect { case Success(s) => s }
          val ss = StaffAssignmentServiceWithDates(successfulShifts)

          val successfulFixedPoints = myFixedPoints.collect { case Success(s) => s }
          val fps = StaffAssignmentServiceWithoutDates(successfulFixedPoints)
          StaffMovements.terminalStaffAt(ss, fps)(myMovements)
        }
      }

      setHandler(outCrunch, new OutHandler {
        override def onPull(): Unit = {
          log.info(s"outCrunch onPull() called")
          pushAndPull()
        }
      })
    }
  }

}

case class StaffAssignment(name: String, terminalName: TerminalName, startDt: MilliDate, endDt: MilliDate, numberOfStaff: Int) {
  def toCsv: String = {
    val startDate: SDateLike = SDate(startDt)
    val endDate: SDateLike = SDate(endDt)
    val startDateString = f"${startDate.getDate()}%02d/${startDate.getMonth()}%02d/${startDate.getFullYear - 2000}%02d"
    val startTimeString = f"${startDate.getHours()}%02d:${startDate.getMinutes()}%02d"
    val endTimeString = f"${endDate.getHours()}%02d:${endDate.getMinutes()}%02d"

    s"$name,$terminalName,$startDateString,$startTimeString,$endTimeString,$numberOfStaff"
  }
}

object StaffDeploymentCalculator {
  type Deployer = (Seq[(String, Int)], Int, Map[String, (Int, Int)]) => Seq[(String, Int)]

  def addDeployments(crunchMinutes: Set[CrunchMinute], deployer: Deployer, available: (MillisSinceEpoch, QueueName) => Int, minMaxDesks: Map[TerminalName, Map[QueueName, (List[Int], List[Int])]]) = crunchMinutes
    .groupBy(_.terminalName)
    .flatMap {
      case (tn, tcrs) =>
        val terminalByMinute: Set[CrunchMinute] = tcrs
          .groupBy(_.minute)
          .flatMap {
            case (minute, mcrs) =>
              val deskRecAndQueueNames: Seq[(QueueName, Int)] = mcrs.map(cm => (cm.queueName, cm.deskRec)).toSeq.sortBy(_._1)
              val queueMinMaxDesks: Map[QueueName, (List[Int], List[Int])] = minMaxDesks.getOrElse(tn, Map())
              val minMaxByQueue: Map[QueueName, (Int, Int)] = queueMinMaxDesks.map {
                case (qn, minMaxList) =>
                  val minDesks = desksForHourOfDayInUKLocalTime(minute, minMaxList._1)
                  val maxDesks = desksForHourOfDayInUKLocalTime(minute, minMaxList._2)
                  (qn, (minDesks, maxDesks))
              }

              val deploymentsAndQueueNames: Map[String, Int] = deployer(deskRecAndQueueNames, available(minute, tn), minMaxByQueue).toMap
              mcrs.map(cm => cm.copy(deployedDesks = Option(deploymentsAndQueueNames(cm.queueName))))
          }.toSet
        terminalByMinute
    }.toSet

  def queueRecsToDeployments(round: Double => Int)
                            (queueRecs: Seq[(String, Int)], staffAvailable: Int, minMaxDesks: Map[String, (Int, Int)]): Seq[(String, Int)] = {
    val totalStaffRec = queueRecs.map(_._2).sum

    queueRecs.foldLeft(List[(String, Int)]()) {
      case (agg, (queue, deskRec)) if agg.length < queueRecs.length - 1 =>
        val ideal = round(staffAvailable * (deskRec.toDouble / totalStaffRec))
        val totalRecommended = agg.map(_._2).sum
        val dr = deploymentWithinBounds(minMaxDesks(queue)._1, minMaxDesks(queue)._2, ideal, staffAvailable - totalRecommended)
        agg :+ Tuple2(queue, dr)
      case (agg, (queue, _)) =>
        val totalRecommended = agg.map(_._2).sum
        val ideal = staffAvailable - totalRecommended
        val dr = deploymentWithinBounds(minMaxDesks(queue)._1, minMaxDesks(queue)._2, ideal, staffAvailable - totalRecommended)
        agg :+ Tuple2(queue, dr)
    }
  }

  def deploymentWithinBounds(min: Int, max: Int, ideal: Int, staffAvailable: Int) = {
    val best = if (ideal < min) min
    else if (ideal > max) max
    else ideal

    if (best > staffAvailable) staffAvailable
    else best
  }

}

object StaffAssignment {
  def apply(name: String, terminalName: TerminalName, startDate: String, startTime: String, endTime: String, numberOfStaff: String = "1"): Try[StaffAssignment] = {
    val staffDeltaTry = Try(numberOfStaff.toInt)
    val ymd = startDate.split("/").toVector

    val tryDMY: Try[(Int, Int, Int)] = Try((ymd(0).toInt, ymd(1).toInt, ymd(2).toInt + 2000))

    for {
      dmy <- tryDMY
      (d, m, y) = dmy

      startDtTry: Try[SDateLike] = parseTimeWithStartTime(startTime, d, m, y)
      endDtTry: Try[SDateLike] = parseTimeWithStartTime(endTime, d, m, y)
      startDt <- startDtTry
      endDt <- endDtTry
      staffDelta: Int <- staffDeltaTry
    } yield {
      val start = MilliDate(startDt.millisSinceEpoch)
      val end = MilliDate(adjustEndDateIfEndTimeIsBeforeStartTime(d, m, y, startDt, endDt).millisSinceEpoch)
      StaffAssignment(name, terminalName, start, end, staffDelta)
    }
  }

  private def adjustEndDateIfEndTimeIsBeforeStartTime(d: Int, m: Int, y: Int, startDt: SDateLike, endDt: SDateLike): SDateLike = {
    if (endDt.millisSinceEpoch < startDt.millisSinceEpoch) {
      SDate(y, m, d, endDt.getHours(), endDt.getMinutes()).addDays(1)
    }
    else {
      endDt
    }
  }

  private def parseTimeWithStartTime(startTime: String, d: Int, m: Int, y: Int): Try[SDateLike] = {
    Try {
      val startT = startTime.split(":").toVector
      val (startHour, startMinute) = (startT(0).toInt, startT(1).toInt)
      val startDt = SDate(y, m, d, startHour, startMinute)
      startDt
    }
  }
}

case class StaffAssignmentParser(rawStaffAssignments: String) {
  val lines: Array[TerminalName] = rawStaffAssignments.split("\n")
  val parsedAssignments: Array[Try[StaffAssignment]] = lines.map(l => {
    l.replaceAll("([^\\\\]),", "$1\",\"").split("\",\"").toList.map(_.trim)
  })
    .filter(parts => parts.length == 5 || parts.length == 6)
    .map {
      case List(description, terminalName, startDay, startTime, endTime) =>
        StaffAssignment(description, terminalName, startDay, startTime, endTime)
      case List(description, terminalName, startDay, startTime, endTime, staffNumberDelta) =>
        StaffAssignment(description, terminalName, startDay, startTime, endTime, staffNumberDelta)
    }
}

trait StaffAssignmentService {
  def terminalStaffAt(terminalName: TerminalName, dateMillis: MillisSinceEpoch): Int
}

case class StaffAssignmentServiceWithoutDates(assignments: Seq[StaffAssignment])
  extends StaffAssignmentService {
  def terminalStaffAt(terminalName: TerminalName, dateMillis: MillisSinceEpoch): Int = assignments.filter(assignment => {
    assignment.terminalName == terminalName &&
      SDate(dateMillis).toHoursAndMinutes() >= SDate(assignment.startDt).toHoursAndMinutes() &&
      SDate(dateMillis).toHoursAndMinutes() <= SDate(assignment.endDt).toHoursAndMinutes()
  }).map(_.numberOfStaff).sum
}

case class StaffAssignmentServiceWithDates(assignments: Seq[StaffAssignment])
  extends StaffAssignmentService {
  def terminalStaffAt(terminalName: TerminalName, dateMillis: MillisSinceEpoch): Int = assignments.filter(assignment => {
    assignment.startDt.millisSinceEpoch <= dateMillis && dateMillis <= assignment.endDt.millisSinceEpoch && assignment.terminalName == terminalName
  }).map(_.numberOfStaff).sum
}

object StaffAssignmentServiceWithoutDates {
  def apply(assignments: Seq[Try[StaffAssignment]]): Try[StaffAssignmentServiceWithoutDates] = {
    if (assignments.exists(_.isFailure))
      Failure(new Exception("Couldn't parse assignments"))
    else {
      Success(StaffAssignmentServiceWithoutDates(assignments.collect { case Success(s) => s }))
    }
  }
}

object StaffAssignmentServiceWithDates {
  def apply(assignments: Seq[Try[StaffAssignment]]): Try[StaffAssignmentServiceWithDates] = {
    if (assignments.exists(_.isFailure))
      Failure(new Exception("Couldn't parse assignments"))
    else {
      Success(StaffAssignmentServiceWithDates(assignments.collect { case Success(s) => s }))
    }
  }
}

object StaffMovements {
  def assignmentsToMovements(staffAssignments: Seq[StaffAssignment]): Seq[StaffMovement] = {
    staffAssignments.flatMap(assignment => {
      val uuid: UUID = UUID.randomUUID()
      StaffMovement(assignment.terminalName, assignment.name + " start", time = assignment.startDt, assignment.numberOfStaff, uuid) ::
        StaffMovement(assignment.terminalName, assignment.name + " end", time = assignment.endDt, -assignment.numberOfStaff, uuid) :: Nil
    }).sortBy(_.time)
  }

  def adjustmentsAt(movements: Seq[StaffMovement])(dateTimeMillis: MillisSinceEpoch): Int = movements.takeWhile(_.time.millisSinceEpoch <= dateTimeMillis).map(_.delta).sum

  def terminalStaffAt(assignmentService: StaffAssignmentService, fixedPointService: StaffAssignmentServiceWithoutDates)
                     (movements: Seq[StaffMovement])
                     (dateTimeMillis: MillisSinceEpoch, terminalName: TerminalName): Int = {
    val baseStaff = assignmentService.terminalStaffAt(terminalName, dateTimeMillis)
    val fixedPointStaff = fixedPointService.terminalStaffAt(terminalName, dateTimeMillis)

    val movementAdjustments = adjustmentsAt(movements.filter(_.terminalName == terminalName))(dateTimeMillis)
    baseStaff - fixedPointStaff + movementAdjustments
  }
}