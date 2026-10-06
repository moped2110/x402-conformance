# x402-conformance – einfach erklärt

Diese Seite erklärt x402-conformance ohne Fachwissen. Wer daran entwickeln will,
findet die technische Anleitung in [DEVELOPER.md](DEVELOPER.md).

## Was ist x402-conformance?

x402-conformance ist ein Prüfprogramm für Web-Dienste, die nach dem
**x402**-Verfahren Geld annehmen. Bei x402 bezahlt ein Programm, zum Beispiel
ein KI-Agent, eine einzelne Web-Anfrage direkt mit digitalem Geld. Es braucht
dafür kein Kundenkonto und kein Abo.

Das Prüfprogramm stellt sich gegenüber einem solchen Dienst wie ein Kunde von
außen. Es prüft, ob der Dienst die Regeln des x402-Protokolls einhält. Aktuell
umfasst sein Prüfkatalog 81 Einzelprüfungen.

## Welches Problem löst es?

Bei x402 geht es um echtes Geld, und viele unabhängige Anbieter sollen
zusammenarbeiten. Kleine Fehler in einem Dienst können teuer werden:

- Der Dienst liefert Inhalte aus, **ohne dass gültig bezahlt wurde**.
- Er nimmt eine **manipulierte Zahlung** an: falscher Betrag, falscher
  Empfänger, abgelaufen oder ein zweites Mal eingereicht.
- Seine Zahlungsaufforderung ist so fehlerhaft, dass **andere Programme sie
  nicht verstehen**.

Das Prüfprogramm findet solche Fehler, bevor echte Kunden darauf stoßen.

## Wie funktioniert es?

Eine x402-Zahlung läuft in vier Schritten:

1. Ein Programm fragt eine geschützte Webadresse an.
2. Der Dienst antwortet mit dem Code **402 „Bezahlung erforderlich"** und
   beschreibt maschinenlesbar, was zu zahlen ist: Betrag, Token, Blockchain,
   Empfänger.
3. Das Programm erstellt eine digital unterschriebene Zahlung und fragt erneut
   an.
4. Der Dienst prüft die Zahlung, oft mit Hilfe eines **Facilitators**, führt sie
   auf der Blockchain aus und liefert den Inhalt.

x402-conformance spielt diesen Ablauf nach. Je nach Einstellung geht es
unterschiedlich weit:

- **Standardprüfung:** Es stellt zwei Anfragen ohne Zahlung und prüft die
  402-Antwort Feld für Feld. Dafür braucht es kein Geld und keine Blockchain.
- **Aktive Prüfung (`--active`):** Es schickt absichtlich ungültige Zahlungen,
  etwa mit falschem Betrag, falschem Empfänger, abgelaufen oder wiederholt. Es
  prüft, dass der Dienst sie alle ablehnt und nichts ausliefert. Unterschrieben
  wird mit einem Wegwerf-Schlüssel ohne Guthaben, es fließt kein Geld.
- **Zahlungsprüfung (`--pay`, `--settle`):** Nur auf Wunsch und nur in einem
  Testnetz oder auf einer lokalen Test-Blockchain, also mit Spielgeld. Es führt eine echte Testzahlung aus und weist auf der
  Blockchain nach, dass genau der richtige Betrag beim richtigen Empfänger
  angekommen ist.

Außerdem prüft es **Facilitatoren**, also die Dienste, die Zahlungen prüfen und
ausführen, sowie **Verzeichnisse** („Bazaar"), in denen bezahlbare Dienste
aufgelistet sind.

Ein Vergleich zur Ergänzung: Das Programm arbeitet wie ein Testkäufer, der
einen Laden besucht. Er prüft, ob die Preisschilder korrekt sind und ob die
Kasse Falschgeld, abgelaufene Gutscheine und doppelt vorgelegte Belege
zurückweist.

## Was bedeuten die Ergebnisse?

Jede Einzelprüfung hat eine Kennung (zum Beispiel `RS-HS-001`), eine Schwere
und einen Verweis auf die Stelle in der x402-Spezifikation.

| Einzelergebnis | Bedeutung |
|---|---|
| **PASS** | Die Regel ist eingehalten. |
| **FAIL** | Die Regel ist verletzt. Die Meldung sagt, was falsch ist und wie man es behebt. |
| **SKIP** | Nicht geprüft, weil eine Voraussetzung fehlt, zum Beispiel weil gar keine 402-Antwort kam. |
| **ERROR** | Die Prüfung selbst ist abgestürzt. Das ist ein Fehler im Prüfprogramm, nicht im Dienst. |

Die Schwere eines Fehlers:

- **kritisch** heißt, Geld oder Sicherheit sind gefährdet;
- **schwer** heißt, die Spezifikation ist verletzt und andere Programme kommen
  nicht zurecht;
- **leicht** ist ein Hinweis zur Robustheit.

Das Gesamturteil, das auch als Zahl ausgegeben wird:

| Gesamturteil | Bedeutung |
|---|---|
| **konform** (`0`) | Keine kritische oder schwere Prüfung ist fehlgeschlagen. |
| **nicht konform** (`1`) | Mindestens eine kritische oder schwere Prüfung ist fehlgeschlagen, oder eine Prüfung ist abgestürzt. Leichte Fehler allein ändern das Urteil nicht. |
| **kein Urteil / INCONCLUSIVE** (`2`) | Es ließ sich nichts Belastbares sagen. Der Bericht nennt den Grund, siehe unten. |

Mögliche Gründe für „kein Urteil":

- Der Dienst war nicht erreichbar.
- Unter der Adresse stand die falsche Art von Dienst.
- Der Dienst spricht kein x402 Version 2.
- Keine Prüfung war anwendbar.
- Die Eingabe war ungültig.
- Ein Punkt wurde bewusst nicht bewertet, weil die Spezifikation dort noch
  ungeklärt ist.

**Ausstehend (PENDING):** Seit Version 0.7.0 kann ein Facilitator auf eine
Zahlung antworten: „abgeschickt, aber noch nicht bestätigt"
(`settlement_pending`). Dabei muss er die Transaktion nennen. Das Prüfprogramm
fragt dann genau einmal mit derselben Zahlung nach.

- Ist es danach immer noch offen, gibt es **kein Urteil** mit dem Grund
  `settlement_pending`. Die Zahlung kann noch ankommen, also wäre jedes Urteil
  geraten.
- Nennt der Facilitator beim Nachfragen eine **andere** Transaktion, hat er die
  Zahlung ein zweites Mal abgeschickt. Das ist ein Fehler.

## Was es nicht tut

- Es bewegt **nie Geld auf einem Hauptnetz**. Zahlungen sind nur in festgelegten
  Testnetzen oder auf einer lokalen Test-Blockchain erlaubt, und das ist im Code
  erzwungen.
- Es **greift nicht an**. Es prüft nur, ob ein Dienst Regeln einhält. Ein
  Bericht enthält ein Urteil, keine Anleitung zum Ausnutzen.
- Es prüft **nicht, ob ein Bezahlsystem intern richtig bucht**, also ob eine
  angekommene Zahlung auch als bezahlt verbucht wird. Das ist die Aufgabe des
  Schwesterprojekts psv.
- Es prüft **nicht den vollständigen Ablauf von Vorautorisierungen**
  („auth-capture": autorisieren, einziehen, freigeben, erstatten). Die Angaben
  dazu prüft es, den Ablauf selbst nicht.
- Ein grünes Ergebnis ist **kein Sicherheits- oder Rechtsgutachten**. Es gilt
  nur für die durchgeführten Prüfungen.

## Kleines Glossar

| Begriff | Erklärung |
|---|---|
| **x402** | Offenes Protokoll, mit dem ein Programm für eine einzelne Web-Anfrage bezahlt. |
| **HTTP 402** | Statuscode des Webs: „Bezahlung erforderlich". x402 nutzt ihn für die Zahlungsaufforderung. |
| **Ressourcen-Server** | Der Dienst mit dem bezahlpflichtigen Inhalt. |
| **Facilitator** | Dienst, der Zahlungen im Auftrag des Anbieters prüft (`/verify`) und auf der Blockchain ausführt (`/settle`). |
| **Settlement** | Die tatsächliche Ausführung der Zahlung auf der Blockchain. |
| **Bazaar / Discovery** | Verzeichnis, in dem bezahlbare Dienste aufgelistet sind. |
| **Blockchain** | Öffentliches, fälschungssicheres Kassenbuch für Überweisungen. |
| **Stablecoin, USDC** | Digitales Geld mit festem Bezug zu einer Währung (USDC zum US-Dollar). |
| **Testnet** | Übungs-Blockchain mit Spielgeld ohne echten Wert, zum Beispiel Base Sepolia. |
| **Mainnet** | Die echte Blockchain mit echtem Geld. Dort zahlt das Prüfprogramm nie. |
| **Signatur** | Digitale Unterschrift, mit der ein Zahler eine Zahlung freigibt. |
| **Spezifikation** | Das verbindliche Regelwerk von x402. Jede Prüfung verweist auf die Stelle, aus der ihre Regel stammt. |
