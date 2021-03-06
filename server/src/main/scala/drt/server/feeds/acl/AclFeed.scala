package server.feeds.acl

import java.io.{ByteArrayInputStream, ByteArrayOutputStream}
import java.nio.charset.StandardCharsets.UTF_8
import java.util.zip.{ZipEntry, ZipInputStream}

import drt.shared.Arrival
import drt.shared.FlightsApi.Flights
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.sftp.SFTPClient
import net.schmizz.sshj.transport.verification.PromiscuousVerifier
import net.schmizz.sshj.xfer.InMemoryDestFile
import org.slf4j.{Logger, LoggerFactory}
import server.feeds.acl.AclFeed.{arrivalsFromCsvContent, contentFromFileName, latestFileForPort, sftpClient}
import services.SDate

import scala.collection.JavaConverters._
import scala.collection.mutable.ArrayBuffer
import scala.util.{Success, Try}

case class AclFeed(ftpServer: String, username: String, path: String, portCode: String) {
  def sftp: SFTPClient = sftpClient(ftpServer, username, path)

  def arrivals: Flights = {
    Flights(arrivalsFromCsvContent(contentFromFileName(sftp, latestFileForPort(sftp, portCode))))
  }
}

object AclFeed {
  val log: Logger = LoggerFactory.getLogger(getClass)

  def sftpClient(ftpServer: String, username: String, path: String): SFTPClient = {
    val ssh = new SSHClient()
    ssh.loadKnownHosts()
    ssh.addHostKeyVerifier(new PromiscuousVerifier())
    ssh.connect(ftpServer)
    ssh.authPublickey(username, path)
    ssh.setTimeout(0)

    ssh.newSFTPClient
  }

  def latestFileForPort(sftp: SFTPClient, portCode: String): String = {
    val portRegex = "([A-Z]{3})[SW][0-9]{2}_HOMEOFFICEROLL180_[0-9]{8}.zip".r
    val dateRegex = "[A-Z]{3}[SW][0-9]{2}_HOMEOFFICEROLL180_([0-9]{8}).zip".r

    val latestFile = sftp
      .ls("/180_Days/").asScala
      .filter(_.getName match {
        case portRegex(pc) if pc == portCode => true
        case _ => false
      })
      .sortBy(_.getName match {
        case dateRegex(date) => date
      })
      .reverse.head
    latestFile.getPath
  }

  def arrivalsFromCsvContent(csvContent: String): List[Arrival] = {
    val flightEntries = csvContent
      .split("\n")
      .drop(1)

    val arrivalEntries = flightEntries
      .map(_.split(",").toList)
      .filter(_.length == 30)
      .filter(_ (AclColIndex.ArrDep) == "A")
      .filter(f => f(AclColIndex.FlightNumber) match {
        case Arrival.flightCodeRegex(_, _, suffix) => !(suffix == "P" || suffix == "F")
        case _ => true
      })

    val arrivals = arrivalEntries
      .map(aclFieldsToArrival)
      .collect { case Success(a) => a }
      .toList

    if (arrivals.nonEmpty) {
      val latestArrival = arrivals.maxBy(_.Scheduled)
      log.info(s"ACL: ${arrivals.length} arrivals. Latest arrival: ${SDate(latestArrival.Scheduled).toLocalDateTimeString()} (${latestArrival.IATA}")
    }
    arrivals
  }

  def contentFromFileName(sftp: SFTPClient, latestFileName: String): String = {
    val outputStream: ByteArrayOutputStream = new ByteArrayOutputStream()

    val file = new InMemoryDestFile {
      def getOutputStream: ByteArrayOutputStream = outputStream
    }

    sftp.get(latestFileName, file)

    val zis: ZipInputStream = new ZipInputStream(new ByteArrayInputStream(outputStream.toByteArray))

    val csvContent: String = unzipStream(zis).toList.head

    dropFileNameFromContent(csvContent)
  }

  def dropFileNameFromContent(content: String) = content
    .split("\n")
    .drop(1)
    .mkString("\n")

  def unzipStream(zipInputStream: ZipInputStream): Seq[String] = {
    try {
      unzipAllFilesInStream(zipInputStream).toList
    } finally {
      zipInputStream.close()
    }
  }

  def unzipAllFilesInStream(unzippedStream: ZipInputStream): Stream[String] = {
    unzipAllFilesInStream(unzippedStream, Option(unzippedStream.getNextEntry))
  }

  def unzipAllFilesInStream(unzippedStream: ZipInputStream, zipEntryOption: Option[ZipEntry]): Stream[String] = {
    zipEntryOption match {
      case None => Stream.empty
      case Some(zipEntry) =>
        val name: String = zipEntry.getName
        val entry: String = getZipEntry(unzippedStream)
        val maybeEntry1: Option[ZipEntry] = Option(unzippedStream.getNextEntry)
        entry #::
          unzipAllFilesInStream(unzippedStream, maybeEntry1)
    }
  }

  def getZipEntry(zis: ZipInputStream): String = {
    val buffer = new Array[Byte](4096)
    val stringBuffer = new ArrayBuffer[Byte]()
    var len: Int = zis.read(buffer)

    while (len > 0) {
      stringBuffer ++= buffer.take(len)
      len = zis.read(buffer)
    }

    new String(stringBuffer.toArray, UTF_8)
  }

  def dateAndTimeToDateTimeIso(date: String, time: String): String = s"${date}T${formatTimeToIso(time)}"

  def formatTimeToIso(time: String): String = f"${time.toInt}%04d".splitAt(2) match {
    case (hour, minute) => s"$hour:$minute:00Z"
  }

  def aclFieldsToArrival(fields: List[String]): Try[Arrival] = {
    Try {
      Arrival(
        Operator = fields(AclColIndex.Operator),
        Status = "ACL Forecast",
        EstDT = "",
        ActDT = "",
        EstChoxDT = "",
        ActChoxDT = "",
        Gate = "",
        Stand = "",
        MaxPax = fields(AclColIndex.MaxPax).toInt,
        ActPax = (fields(AclColIndex.MaxPax).toInt * fields(AclColIndex.LoadFactor).toDouble).round.toInt,
        TranPax = 0,
        RunwayID = "",
        BaggageReclaimId = "",
        FlightID = (fields(AclColIndex.FlightNumber) + fields(AclColIndex.Date) + fields(AclColIndex.Time) + fields(AclColIndex.Origin)).hashCode,
        AirportID = fields(AclColIndex.Airport),
        Terminal = s"T${
          fields(AclColIndex.Terminal).take(1)
        }",
        rawICAO = fields(AclColIndex.FlightNumber),
        rawIATA = fields(AclColIndex.FlightNumber),
        Origin = fields(AclColIndex.Origin),
        SchDT = dateAndTimeToDateTimeIso(fields(AclColIndex.Date), fields(AclColIndex.Time)),
        Scheduled = SDate(dateAndTimeToDateTimeIso(fields(AclColIndex.Date), fields(AclColIndex.Time))).millisSinceEpoch,
        PcpTime = 0,
        None
      )
    }
  }

  object AclColIndex {

    val allFields: Map[String, Int] = List(
      "A/C", "ACReg", "Airport", "ArrDep", "CreDate",
      "Date", "DOOP", "EditDate", "Icao Aircraft Type", "Icao Last/Next Station",
      "Icao Orig/Dest Station", "LastNext", "LastNextCountry", "Ope", "OpeGroup",
      "OpeName", "OrigDest", "OrigDestCountry", "Res", "Season",
      "Seats", "ServNo", "ST", "ove.ind", "Term",
      "Time", "TurnOpe", "TurnServNo", "OpeFlightNo", "LoadFactor"
    ).zipWithIndex.toMap

    val MaxPax: Int = allFields("Seats")
    val LoadFactor: Int = allFields("LoadFactor")
    val FlightNumber: Int = allFields("OpeFlightNo")
    val Date: Int = allFields("Date")
    val Time: Int = allFields("Time")
    val Operator: Int = allFields("Ope")
    val Origin: Int = allFields("OrigDest")
    val Airport: Int = allFields("Airport")
    val Terminal: Int = allFields("Term")
    val ArrDep: Int = allFields("ArrDep")
    val FlightType: Int = allFields("ST")
  }

}
