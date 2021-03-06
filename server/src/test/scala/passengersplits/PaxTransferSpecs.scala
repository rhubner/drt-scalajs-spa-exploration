package passengersplits

import drt.shared.{ApiPaxTypeAndQueueCount, DqEventCodes, Queues}
import org.specs2._
import org.specs2.specification.script.StandardDelimitedStepParsers
import passengersplits.core.SplitsCalculator
import passengersplits.parsing.VoyageManifestParser.{PassengerInfoJson, VoyageManifest}

class PaxTransferSpecs extends Specification with specification.dsl.GWT with StandardDelimitedStepParsers {
  def is =
    s2"""
    This is a specification of passenger splits with transfer passengers from the DQ Advance Passenger Info (API) feed

        |As an LHR SO user of DRT I would like to see the transfer passengers that are arriving for a flight.
        |The transfer passengers should be removed from the API pax numbers arriving at the PCP and displayed separately in a Transfer column.
        |This will ensure that I know the number of passengers that should be seen at PCP from a flight,
        |it will also highlight the number of additional passengers that could be seen by the
        |PCP if the arrival of the flight is delayed and the passengers miss their connecting flight.
        |
        |opt - It would be useful to see the number of international and domestic transfers - hover over could be used?
        |
        |TransferQueue
        | - $transferPaxGoToATransferQueue
        |
        | - $transferPaxOnANonLHRFlightDoNOTGoToATransferQueue
    """

  def transferPaxGoToATransferQueue =
    s2"""
    - Given A Flight to LHR $createLHRFlight
     And the flight has passengers
     And a Passenger is from {DEU} {InTransit} disembarking {BCN} $addPassenger
     And a Passenger is from {DEU} {NotInTransit} disembarking {STN} $addPassenger
    When we calculate the splits $calcSplits
    Then we do NOT see them in the split counts
    SplitCounts are eeaDesk {1} transfers {1} $assertSplits
    """

  def transferPaxOnANonLHRFlightDoNOTGoToATransferQueue =
    s2"""
    - We only want this feature enabled for LHR
    - Given A Flight $createNonLHRFlight
     And the flight has passengers
     And a Passenger is from {DEU} {InTransit} disembarking {BCN} $addPassenger
     And a Passenger is from {DEU} {NotInTransit} disembarking {EDI} $addPassenger
    When we calculate the splits $calcSplits
    Then we do NOT see them in the split counts
    SplitCounts are eeaDesk {2} and no transfers  $assertSplitsWithNoTransfers
    """

  var currentFlight: Option[VoyageManifest] = None
  var calculatedSplits: Seq[ApiPaxTypeAndQueueCount] = Nil

  def splitsByQueue = calculatedSplits.groupBy(_.queueType).mapValues(v => v.map(_.paxCount).sum)

  def createLHRFlight = step {
    currentFlight = Some(VoyageManifest(DqEventCodes.CheckIn, "LHR", "MON", "123", "RYR", "2017-05-02", "10:33:00", Nil))
  }

  def createNonLHRFlight = step {
    currentFlight = Some(VoyageManifest(DqEventCodes.CheckIn, "EDI", "MON", "123", "RYR", "2017-05-02", "10:33:00", Nil))
  }

  def addPassenger = step(threeStrings) {
    case (countryCode: String, transferState: String, disembarkation: String) => {

      val inTransit = transferState match {
        case "InTransit" => "Y"
        case "NotInTransit" => "N"
      }

      val newPassenger = PassengerInfoJson(Some("P"), countryCode, EEAFlag = "EEA", None, Some(disembarkation), inTransit, PassengerIdentifier = None)
      currentFlight = currentFlight.map(f => f.copy(PassengerList = newPassenger :: f.PassengerList))
    }
  }

  def calcSplits = step {
    for (flight <- currentFlight) {
      calculatedSplits = SplitsCalculator.convertVoyageManifestIntoPaxTypeAndQueueCounts("STN", flight)
    }
  }

  def assertSplits = example(twoInts) {
    case (eea: Int, transfer: Int) => Map(Queues.EeaDesk -> eea, Queues.Transfer -> transfer) must_== splitsByQueue
  }

  def assertSplitsWithNoTransfers = example(anInt) {
    case (eea: Int) => Map(Queues.EeaDesk -> eea) must_== splitsByQueue
  }

}
