package services

import drt.shared.CrunchApi.{CrunchMinute, MillisSinceEpoch}
import drt.shared.FlightsApi.{QueueName, TerminalName}
import drt.shared.Queues
import org.specs2.mutable.Specification
import services.graphstages.{StaffAssignmentService, StaffSources}
import services.graphstages.StaffDeploymentCalculator._

import scala.collection.immutable.List

case class TestStaffAssignmentService(staff: Int) extends StaffAssignmentService {
  override def terminalStaffAt(terminalName: TerminalName, dateMillis: MillisSinceEpoch): Int = staff
}

class StaffDeploymentSpec extends Specification {
  val testStaffService = TestStaffAssignmentService(0)
  val minMaxDesks = Map(
    "T1" -> Map(
      Queues.EeaDesk -> ((List.fill[Int](24)(1), List.fill[Int](24)(10))),
      Queues.NonEeaDesk -> ((List.fill[Int](24)(1), List.fill[Int](24)(10))),
      Queues.EGate -> ((List.fill[Int](24)(1), List.fill[Int](24)(10)))),
    "T2" -> Map(
      Queues.EeaDesk -> ((List.fill[Int](24)(1), List.fill[Int](24)(10))),
      Queues.NonEeaDesk -> ((List.fill[Int](24)(1), List.fill[Int](24)(10))),
      Queues.EGate -> ((List.fill[Int](24)(1), List.fill[Int](24)(10)))))

  private val staffAvailable = 25
  "Given a set of CrunchMinutes representing a single terminal with 3 queues at one minute " +
  "When I ask to add deployments to them " +
  "Then I see the staff available distributed to the appropriate queues" >> {
    val crunchMinutes = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 5),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 10),
      crunchMinute("T1", Queues.EGate, 0, 12)
    ).map(cm => (cm.key, cm)).toMap
    val deployer: Deployer = queueRecsToDeployments(_.toInt)
    val staffSources = StaffSources(testStaffService, testStaffService, testStaffService, (_, _) => staffAvailable)
    val result = addDeployments(crunchMinutes, deployer, Option(staffSources), minMaxDesks).values.toSet

    val expected = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 5, Some(4)),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 10, Some(10)),
      crunchMinute("T1", Queues.EGate, 0, 12, Some(10))
    )

    result === expected
  }

  "Given a set of CrunchMinutes with recs all zero " +
  "When I ask to add deployments to them " +
  "Then I see the staff available distributed evenly across the queues" >> {
    val crunchMinutes = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 0),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 0),
      crunchMinute("T1", Queues.EGate, 0, 0)
    ).map(cm => (cm.key, cm)).toMap
    val deployer: Deployer = queueRecsToDeployments(_.toInt)
    val staffSources = StaffSources(testStaffService, testStaffService, testStaffService, (_, _) => staffAvailable)
    val result = addDeployments(crunchMinutes, deployer, Option(staffSources), minMaxDesks).values.toSet

    val expected = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 0, Some(8)),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 0, Some(9)),
      crunchMinute("T1", Queues.EGate, 0, 0, Some(8))
    )

    result === expected
  }

  "Given a set of CrunchMinutes representing a single terminal with 2 queues at two minutes " +
    "When I ask to add deployments to them " +
    "Then I see the staff available distributed to the appropriate queues" >> {
    val crunchMinutes = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 5),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 10),
      crunchMinute("T1", Queues.EeaDesk, 60000, 2),
      crunchMinute("T1", Queues.NonEeaDesk, 60000, 15)
    ).map(cm => (cm.key, cm)).toMap
    val deployer: Deployer = queueRecsToDeployments(_.toInt)
    val staffSources = StaffSources(testStaffService, testStaffService, testStaffService, (_, _) => staffAvailable)

    val result = addDeployments(crunchMinutes, deployer, Option(staffSources), minMaxDesks).values.toSet

    val expected = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 5, Some(8)),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 10, Some(10)),
      crunchMinute("T1", Queues.EeaDesk, 60000, 2, Some(2)),
      crunchMinute("T1", Queues.NonEeaDesk, 60000, 15, Some(10))
    )

    result === expected
  }

  "Given a set of CrunchMinutes representing two terminals with 2 queues at two minutes " +
    "When I ask to add deployments to them " +
    "Then I see the staff available distributed to the appropriate queues" >> {
    val crunchMinutes = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 5),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 10),
      crunchMinute("T1", Queues.EeaDesk, 60000, 2),
      crunchMinute("T1", Queues.NonEeaDesk, 60000, 15),
      crunchMinute("T2", Queues.EeaDesk, 0, 6),
      crunchMinute("T2", Queues.NonEeaDesk, 0, 9),
      crunchMinute("T2", Queues.EeaDesk, 60000, 8),
      crunchMinute("T2", Queues.NonEeaDesk, 60000, 18)
    ).map(cm => (cm.key, cm)).toMap
    val deployer: Deployer = queueRecsToDeployments(_.toInt)

    val staffSources = StaffSources(testStaffService, testStaffService, testStaffService, (_, _) => staffAvailable)
    val result = addDeployments(crunchMinutes, deployer, Option(staffSources), minMaxDesks).values.toSet

    val expected = Set(
      crunchMinute("T1", Queues.EeaDesk, 0, 5, Some(8)),
      crunchMinute("T1", Queues.NonEeaDesk, 0, 10, Some(10)),
      crunchMinute("T1", Queues.EeaDesk, 60000, 2, Some(2)),
      crunchMinute("T1", Queues.NonEeaDesk, 60000, 15, Some(10)),
      crunchMinute("T2", Queues.EeaDesk, 0, 6, Some(10)),
      crunchMinute("T2", Queues.NonEeaDesk, 0, 9, Some(10)),
      crunchMinute("T2", Queues.EeaDesk, 60000, 8, Some(7)),
      crunchMinute("T2", Queues.NonEeaDesk, 60000, 18, Some(10))
    )

    result === expected
  }

  def crunchMinute(terminalName: TerminalName,
                   queueName: QueueName,
                   minute: Long,
                   deskRec: Int,
                   simDesks: Option[Int] = None): CrunchMinute = CrunchMinute(
    terminalName = terminalName,
    queueName = queueName,
    minute = minute,
    paxLoad = 0,
    workLoad = 0d,
    deskRec = deskRec,
    waitTime = 0,
    deployedDesks = simDesks
  )
}
