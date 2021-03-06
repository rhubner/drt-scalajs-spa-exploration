package drt.client.components

import diode.data.Ready
import drt.client.services.JSDateConversions.SDate
import drt.client.services.RootModel
import drt.shared.CrunchApi.CrunchState
import drt.shared.FlightsApi.FlightsWithSplits
import drt.shared.SplitRatiosNs.SplitSources
import drt.shared._
import utest.{TestSuite, _}


object BigSummaryBoxTests extends TestSuite {

  import ApiFlightGenerator._
  import BigSummaryBoxes._

  def tests = TestSuite {
    "Summary for the next 3 hours" - {
      "Given a rootModel with flightsWithSplits with flights arriving 2017-05-01T12:01Z onwards" - {
        "Given 0 flights" - {
          val rootModel = RootModel(crunchStatePot = Ready(CrunchState(Set(), Set(), Set())))

          "AND a current time of 2017-05-01T12:00" - {
            val now = SDate(2016, 5, 1, 12)
            val nowPlus3Hours = now.addHours(3)

            "Then we can get a number of flights arriving in that period" - {
              val countOfFlights = rootModel.crunchStatePot.map(_.flights.count(f => {
                val flightDt = SDate.parse(f.apiFlight.SchDT)
                now.millisSinceEpoch <= flightDt.millisSinceEpoch && flightDt.millisSinceEpoch <= nowPlus3Hours.millisSinceEpoch
              }))
              assert(countOfFlights == Ready(0))
            }
          }
        }
        "Given 3 flights" - {
          import ApiFlightGenerator._

          val apiFlight1 = apiFlight("2017-05-01T12:05Z", FlightID = 1, ActPax = 200)
          val apiFlight2 = apiFlight("2017-05-01T13:05Z", FlightID = 2, ActPax = 300)
          val apiFlight3 = apiFlight("2017-05-01T13:20Z", FlightID = 3, ActPax = 40)

          val rootModel = RootModel(crunchStatePot = Ready(CrunchState(
            flights = Set(
              ApiFlightWithSplits(apiFlight1, Set()),
              ApiFlightWithSplits(apiFlight2, Set()),
              ApiFlightWithSplits(apiFlight3, Set())),
            crunchMinutes = Set(),
            staffMinutes = Set())))

          "AND a current time of 2017-05-01T12:00" - {
            val now = SDate.parse("2017-05-01T12:00Z")
            val nowPlus3Hours = now.addHours(3)

            "Then we can get a number of flights arriving in that period" - {
              val countOfFlights = countFlightsInPeriod(rootModel, now, nowPlus3Hours)
              val expected = Ready(3)
              assert(countOfFlights == expected)
            }
            "And we can get the total pax to the PCP" - {
              val countOfPax = countPaxInPeriod(rootModel, now, nowPlus3Hours)
              assert(countOfPax == Ready(200 + 300 + 40))
            }
          }
        }
        "Given 3 flights with a nonZero PcpTime we use the pcpTime " - {
          import ApiFlightGenerator._

          def mkMillis(t: String) = SDate.parse(t).millisSinceEpoch

          val apiFlightPcpBeforeNow = apiFlight("2017-05-01T11:40Z", FlightID = 0, ActPax = 7, PcpTime = mkMillis("2017-05-01T11:40Z"))
          val apiFlight0aPcpAfterNow = apiFlight("2017-05-01T11:40Z", FlightID = 1, ActPax = 11, PcpTime = mkMillis("2017-05-01T12:05Z"))
          val apiFlight1 = apiFlight("2017-05-01T12:05Z", FlightID = 2, ActPax = 200, PcpTime = mkMillis("2017-05-01T12:05Z"))
          val apiFlight2 = apiFlight("2017-05-01T13:05Z", FlightID = 3, ActPax = 300, PcpTime = mkMillis("2017-05-01T13:15Z"))
          val apiFlight3 = apiFlight("2017-05-01T13:20Z", FlightID = 4, ActPax = 40, PcpTime = mkMillis("2017-05-01T13:22Z"))


          val rootModel = RootModel(crunchStatePot = Ready(CrunchState(
            flights = Set(
              ApiFlightWithSplits(apiFlightPcpBeforeNow, Set()),
              ApiFlightWithSplits(apiFlight0aPcpAfterNow, Set()),
              ApiFlightWithSplits(apiFlight1, Set()),
              ApiFlightWithSplits(apiFlight2, Set()),
              ApiFlightWithSplits(apiFlight3, Set())),
            crunchMinutes = Set(),
            staffMinutes = Set())))

          "AND a current time of 2017-05-01T12:00" - {
            val now = SDate.parse("2017-05-01T12:00Z")
            val nowPlus3Hours = now.addHours(3)

            "Then we can get a number of flights arriving in that period" - {
              val countOfFlights = countFlightsInPeriod(rootModel, now, nowPlus3Hours)
              val expected = Ready(4)
              assert(countOfFlights == expected)
            }
            "And we can get the total pax to the PCP" - {
              val countOfPax = countPaxInPeriod(rootModel, now, nowPlus3Hours)
              assert(countOfPax == Ready(11 + 200 + 300 + 40))
            }
          }
        }
        "Given 3 flights with a nonZero PcpTime we use the pcpTime " - {
          "AND we can filter by Terminal - we're interested in T1" - {
            val ourTerminal = "T1"

            import ApiFlightGenerator._

            def mkMillis(t: String) = SDate.parse(t).millisSinceEpoch

            val apiFlight1 = apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 200, PcpTime = mkMillis("2017-05-01T12:05Z"))
            val apiFlight2 = apiFlight("2017-05-01T13:05Z", Terminal = "T1", FlightID = 3, ActPax = 300, PcpTime = mkMillis("2017-05-01T13:15Z"))
            val notOurTerminal = apiFlight("2017-05-01T13:20Z", Terminal = "T4", FlightID = 4, ActPax = 40, PcpTime = mkMillis("2017-05-01T13:22Z"))

            val flights = Set(
              ApiFlightWithSplits(apiFlight1, Set()),
              ApiFlightWithSplits(apiFlight2, Set()),
              ApiFlightWithSplits(notOurTerminal, Set()))
            val rootModel = RootModel(crunchStatePot = Ready(CrunchState(flights = flights, crunchMinutes = Set(), staffMinutes = Set())))


            "AND a current time of 2017-05-01T12:00" - {
              val now = SDate.parse("2017-05-01T12:00Z")
              val nowPlus3Hours = now.addHours(3)

              "Then we can get a number of flights arriving in that period" - {
                val flightsPcp = flightsInPeriod(flights.toList, now, nowPlus3Hours)
                val flightsInTerminal = flightsAtTerminal(flightsPcp, ourTerminal)
                val countOfFlights = flightsInTerminal.length
                val expected = 2
                assert(countOfFlights == expected)
              }
            }
          }
        }
        "Given 3 flights " - {
          "And they have splits" - {
            "Then we can aggregate the splits for a graph" - {
              val ourTerminal = "T1"

              import ApiFlightGenerator._

              def mkMillis(t: String) = SDate.parse(t).millisSinceEpoch

              val apiFlight1 = apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 200, PcpTime = mkMillis("2017-05-01T12:05Z"))
              val apiFlight2 = apiFlight("2017-05-01T13:05Z", Terminal = "T1", FlightID = 3, ActPax = 300, PcpTime = mkMillis("2017-05-01T13:15Z"))

              val splits1 = ApiSplits(Set(ApiPaxTypeAndQueueCount(PaxTypes.NonVisaNational, Queues.NonEeaDesk, 41, None),
                ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 23, None)),
                SplitSources.ApiSplitsWithHistoricalEGateAndFTPercentages, Option(DqEventCodes.DepartureConfirmed), PaxNumbers)

              val splits2 = ApiSplits(Set(
                ApiPaxTypeAndQueueCount(PaxTypes.NonVisaNational, Queues.NonEeaDesk, 11, None),
                ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 17, None))
                , SplitSources.ApiSplitsWithHistoricalEGateAndFTPercentages, Option(DqEventCodes.DepartureConfirmed), PaxNumbers)

              val flights = FlightsWithSplits(
                List(ApiFlightWithSplits(apiFlight1, Set(splits1)),
                  ApiFlightWithSplits(apiFlight2, Set(splits2))))

              val aggSplits = aggregateSplits(ArrivalHelper.bestPax)(flights.flights)

              val expectedAggSplits = Map(
                PaxTypeAndQueue(PaxTypes.NonVisaNational, Queues.NonEeaDesk) -> (41 + 11),
                PaxTypeAndQueue(PaxTypes.EeaMachineReadable, Queues.EeaDesk) -> (23 + 17))

              assert(aggSplits == expectedAggSplits)
            }
          }
        }
        "Given 2 flights " - {
          "And they have percentage splits" - {
            "Then we can aggregate the splits by multiply the % against the bestPax so that we can show them in a graph" - {

              import ApiFlightGenerator._

              def mkMillis(t: String) = SDate.parse(t).millisSinceEpoch

              val flights = List(
                ApiFlightWithSplits(apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 100, PcpTime = mkMillis("2017-05-01T12:05Z")),
                  Set(ApiSplits(Set(
                    ApiPaxTypeAndQueueCount(PaxTypes.NonVisaNational, Queues.NonEeaDesk, 30, None),
                    ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 70, None)),
                    SplitSources.Historical, None, Percentage))),
                ApiFlightWithSplits(apiFlight("2017-05-01T13:05Z", Terminal = "T1", FlightID = 3, ActPax = 100, PcpTime = mkMillis("2017-05-01T13:15Z")),
                  Set(ApiSplits(Set(
                    ApiPaxTypeAndQueueCount(PaxTypes.NonVisaNational, Queues.NonEeaDesk, 40, None),
                    ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 60, None)),
                    SplitSources.Historical, None, Percentage))))

              val aggSplits = aggregateSplits(ArrivalHelper.bestPax)(flights)

              val expectedAggSplits = Map(
                PaxTypeAndQueue(PaxTypes.NonVisaNational, Queues.NonEeaDesk) -> (30 + 40),
                PaxTypeAndQueue(PaxTypes.EeaMachineReadable, Queues.EeaDesk) -> (70 + 60))

              assert(aggSplits == expectedAggSplits)
            }
          }
        }
        "Given 2 flights " - {
          "And we're using the LHR tranPax aware bestpax" - {
            "And they have API PaxNo splits including a transfer split" - {
              "And they have tranpax" - {
                "Then we can aggregate the splits by adding them up - we also filter out the transfer split" - {

                  import ApiFlightGenerator._

                  def mkMillis(t: String) = SDate.parse(t).millisSinceEpoch

                  val flights = List(
                    ApiFlightWithSplits(apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 300, TranPax = 100, PcpTime = mkMillis("2017-05-01T12:05Z")),
                      Set(ApiSplits(Set(
                        ApiPaxTypeAndQueueCount(PaxTypes.NonVisaNational, Queues.NonEeaDesk, 60, None),
                        ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 120, None),
                        ApiPaxTypeAndQueueCount(PaxTypes.Transit, Queues.Transfer, 20, None)),
                        SplitSources.Historical, None, PaxNumbers))))

                  val aggSplits = aggregateSplits(ArrivalHelper.bestPax)(flights)

                  val expectedAggSplits = Map(
                    PaxTypeAndQueue(PaxTypes.NonVisaNational, Queues.NonEeaDesk) -> 60,
                    PaxTypeAndQueue(PaxTypes.EeaMachineReadable, Queues.EeaDesk) -> 120)

                  assert(aggSplits == expectedAggSplits)
                }
              }
            }
          }
        }
        "Best Pax Calculations " - {

          "Given a flight " - {
            "AND it has PaxNumber splits at the the head of it's split list" - {
              "Then we use the sum of it's splits" - {
                val apiFlight1 = apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 100, PcpTime = mkMillis("2017-05-01T12:05Z"))

                val splits1 = ApiSplits(Set(ApiPaxTypeAndQueueCount(PaxTypes.NonVisaNational, Queues.NonEeaDesk, 41, None),
                  ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 23, None)),
                  SplitSources.ApiSplitsWithHistoricalEGateAndFTPercentages, Option(DqEventCodes.DepartureConfirmed), PaxNumbers)

                val apiFlightWithSplits = ApiFlightWithSplits(apiFlight1, Set(splits1))

                val pax = bestFlightSplitPax(ArrivalHelper.bestPax)(apiFlightWithSplits)

                val expectedPax = 23 + 41

                assert(pax == expectedPax)
              }
            }
          }
          "Given a flight " - {
            "AND it has Percentage splits at the head of it's list" - {
              "AND it has act pax " - {
                "Then we use act pax from the flight" - {
                  val apiFlight1 = apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 100, PcpTime = mkMillis("2017-05-01T12:05Z"))
                  val splits1 = ApiSplits(Set(ApiPaxTypeAndQueueCount(PaxTypes.NonVisaNational, Queues.NonEeaDesk, 0.2, None),
                    ApiPaxTypeAndQueueCount(PaxTypes.EeaMachineReadable, Queues.EeaDesk, 0.7, None)),
                    SplitSources.ApiSplitsWithHistoricalEGateAndFTPercentages, Option(DqEventCodes.DepartureConfirmed), Percentage)

                  val apiFlightWithSplits = ApiFlightWithSplits(apiFlight1, Set(splits1))

                  val pax = bestFlightSplitPax(ArrivalHelper.bestPax)(apiFlightWithSplits)

                  val expectedPax = 100

                  assert(pax == expectedPax)
                }
              }
            }
          }
          "Given a flight " - {
            "AND it has no splits " - {
              "AND it has act pax " - {
                "Then we use act pax from the flight" - {
                  val apiFlight1 = apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 100, PcpTime = mkMillis("2017-05-01T12:05Z"))
                  val apiFlightWithSplits = ApiFlightWithSplits(apiFlight1, Set())

                  val pax = bestFlightSplitPax(ArrivalHelper.bestPax)(apiFlightWithSplits)

                  val expectedPax = 100

                  assert(pax == expectedPax)
                }
              }
            }
          }
          "DRT-4632 Given we're running for LHR" - {
            val bestPaxFn = ArrivalHelper.bestPax _
            "AND we have a flight " - {
              "AND it has no splits " - {
                "AND it has 100 act pax AND it has 60 transpax" - {
                  "Then we get pcpPax of 40 " - {
                    val apiFlight1 = apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 100, TranPax = 60, PcpTime = mkMillis("2017-05-01T12:05Z"))
                    val apiFlightWithSplits = ApiFlightWithSplits(apiFlight1, Set())

                    val pax = bestFlightSplitPax(bestPaxFn)(apiFlightWithSplits)

                    val expectedPax = 40

                    assert(pax == expectedPax)
                  }
                }
              }
            }
          }
          "Given a flight " - {
            "AND it has no splits " - {
              "AND it has not got act pax " - {
                "Then we use max pax from the flight" - {
                  val apiFlight1 = apiFlight("2017-05-01T12:05Z", Terminal = "T1", FlightID = 2, ActPax = 0, MaxPax = 134, PcpTime = mkMillis("2017-05-01T12:05Z"))
                  val apiFlightWithSplits = ApiFlightWithSplits(apiFlight1, Set())

                  val pax = bestFlightSplitPax(ArrivalHelper.bestPax)(apiFlightWithSplits)

                  val expectedPax = 134

                  assert(pax == expectedPax)
                }
              }
            }
          }
        }
      }
    }
  }

  def mkMillis(t: String) = SDate.parse(t).millisSinceEpoch
}

object ApiFlightGenerator {

  def apiFlight(
                 SchDT: String,
                 Operator: String = "",
                 Status: String = "",
                 EstDT: String = "",
                 ActDT: String = "",
                 EstChoxDT: String = "",
                 ActChoxDT: String = "",
                 Gate: String = "",
                 Stand: String = "",
                 MaxPax: Int = 1,
                 ActPax: Int = 0,
                 TranPax: Int = 0,
                 RunwayID: String = "",
                 BaggageReclaimId: String = "",
                 FlightID: Int = 2,
                 AirportID: String = "STN",
                 Terminal: String = "1",
                 rawICAO: String = "",
                 iataFlightCode: String = "BA123",
                 Origin: String = "",
                 PcpTime: Long = 0): Arrival =
    Arrival(
      Operator = Operator,
      Status = Status,
      EstDT = EstDT,
      ActDT = ActDT,
      EstChoxDT = EstChoxDT,
      ActChoxDT = ActChoxDT,
      Gate = Gate,
      Stand = Stand,
      MaxPax = MaxPax,
      ActPax = ActPax,
      TranPax = TranPax,
      RunwayID = RunwayID,
      BaggageReclaimId = BaggageReclaimId,
      FlightID = FlightID,
      AirportID = AirportID,
      Terminal = Terminal,
      rawICAO = rawICAO,
      rawIATA = iataFlightCode,
      Origin = Origin,
      PcpTime = if (PcpTime != 0) PcpTime else SDate.parse(SchDT).millisSinceEpoch,
      SchDT = SchDT,
      Scheduled = if (SchDT != "") SDate.parse(SchDT).millisSinceEpoch else 0L
    )

}
