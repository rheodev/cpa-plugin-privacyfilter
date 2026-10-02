# Prüfplan des Testlabors

Ziel ist ein Plugin, das im Dauerbetrieb keinen Schaden anrichtet: keine vertraulichen Werte hinaus, keine verfälschten Befehle zurück, kein Blockieren gültiger Anfragen, kein Datenverlust im Stream. Was geprüft ist und was dabei herauskam, steht in [BEFUNDE.md](BEFUNDE.md); diese Datei sagt, wo was liegt und was noch fehlt, damit eine Sitzung ohne Vorgeschichte weitermachen kann.

Der Stand: von zwanzig Befunden sind neunzehn behoben, und die Lücke im Netz der Pfadebene ist zum größeren Teil geschlossen, weil die Pfadebene bloße Pfade an ihrer Form erkennt; was offen bleibt, der bloße Verzeichnispfad ohne Datei, der Diff-Kopf, Adressen und Windows, steht im README als Grenze. Zehn Tests im Paket `harm` zeigen, was ein Term mit Sonderzeichen anrichtet; sie überspringen sich selbst, bis `PRIVACYFILTER_OPEN_FINDINGS` gesetzt ist, weil der Lader einen solchen Wert abweist und die Tests die Wirkung dokumentieren, die er verhindert.


---

# Wie hier gearbeitet wird

Jeder Prüfbereich hat ein eigenes Paket. Das ist keine Förmlichkeit: liegen zwei Arbeiten im selben Paket, genügt eine doppelte Hilfsfunktion, und der Bau schlägt für beide fehl. Die gemeinsamen Helfer stehen in [lab/lab.go](lab/lab.go) und werden als `internal/testlab/lab` importiert.

Ein Test, der einen Fehler zeigt, ruft als erste Zeile `skipOpenFinding` und bleibt damit im Baum, ohne die Suite rot zu färben. Ein Test, der Verhalten festhält, über das noch zu entscheiden ist, bleibt grün und protokolliert mit `t.Logf`. Wer einen Befund findet, schreibt ihn in [BEFUNDE.md](BEFUNDE.md): was passiert, unter welchen Umständen, wie schwer es wiegt, wo der Test steht, welche Kur vorgeschlagen wird. Wer einen kuriert, streicht den Aufruf, sieht den Test grün werden und trägt im Kapitel nach, womit.

Ein Wert, auf den es ankommt, wird zur Laufzeit aus Zahlen zusammengesetzt und nicht als Literal geschrieben. Jede Datei dieses Verzeichnisses läuft auf ihrem Weg auf die Platte selbst durch den Filter, und ein Literal kann dort als etwas anderes ankommen. `lab.V4` und `lab.MAC` sind dafür da, neben `payload` die Funktion `v4`. Aus derselben Ursache ist ein Verzeichnisname in einem Befehl unzuverlässig: `go test ./... -run <TestName>` führt sicher zum Ziel, ein getippter Paketpfad nicht immer. Und ganze Dateien verschiebt man mit `cp`; was nie durch das Modell läuft, kann auch nicht verfälscht ankommen.


---

# Was in den Paketen liegt

`basics` trägt die erste Runde: Round-Trip und Tokengrenzen, Unicode, die Formen des Systembetriebs, den Alltag einer Sitzung mit Patch und `old_string`, Adressbereiche, Nebenläufigkeit, Maßstab, die Formtreue je Art und den Ersatzwert, der im Gesprächsverlauf hängen bleibt. `layers` prüft das Zusammenspiel der Erkennungsschichten samt der Vorschicht, die Mailadressen befördert. `harm` prüft, was ein Originalwert anrichtet, wenn er in Befehle, Patches, Konfigurationszeilen und Suchmuster gerät. `props` hält zehn Fuzz-Ziele mit ihrem Korpus für die Eigenschaften, die über zufälligen Eingaben gelten müssen. `config` prüft die Konstruktoren gegen fehlerhafte Konfiguration. `lab` hält die gemeinsamen Helfer und ist das einzige Paket ohne Tests.

Zwei Bereiche liegen außerhalb dieses Verzeichnisses, weil sie zu dem Paket gehören, das sie messen: die Proben der JSON-Ebene stehen neben `payload` in `deny_test.go`, `walk_test.go`, `json_edge_test.go` und den vier `edge_*`-Dateien, die des Streams im Wurzelpaket in `stream_sequence_test.go`, `stream_blocks_test.go`, `stream_abort_test.go` samt Fixture und Adapter.

Ausführen mit `go test ./...`, gern mit `-race`. Dann aber `-short` dazu: `TestLargeBody` in `internal/leaktest` schiebt einen Body von etwa 31 MiB durch den ganzen Hinweg und braucht unter dem Race-Detektor allein 568 Sekunden, sodass das Paket die Zehn-Minuten-Frist überläuft, die `go test` voreingestellt hat. Ein Fehler ist das nicht: mit `-timeout 45m` läuft der Test durch, und kein einziges Datenrennen wird gemeldet. Ein Fuzz-Lauf über das Erwartete hinaus geht mit `-run Fuzz -fuzz FuzzPropsPseudonymShape -fuzztime 60s` auf das Paket `props`.


---

# Was offen bleibt

Der Weg durch den echten HTTP-Pfad ist von hier nicht zu prüfen: ob `on_error: block` bei einem fehlerhaften Body wirklich blockt, ob die Grenze von zweiunddreißig Megabyte greift, was ein mitten im Stream abgebrochener Anbieter mit dem zurückgehaltenen Rest macht, ob das Prüfprotokoll schreibt, was es schreiben soll, und ob der Host einen fehlerhaften Chunk unverändert weiterreicht und einen unterdrückten wirklich unterdrückt. Dazu die Nebenläufigkeit eines Streamzustands unter den Aufrufen des Hosts.

Ungeprüft sind ferner betterleaks hinter seinem Build-Tag und alles, was nicht dem Anthropic-Schema folgt. Die Race beim Neuladen der Konfiguration im laufenden Host bleibt eine Frage für das lebende System; die Nebenläufigkeit der Bausteine ist geprüft und hält.

Was die Befunde selbst angeht, liegt die Reihenfolge im zweiten Kapitel des Berichts. Sie ist abgearbeitet; die Versalschrift mit SS hat der Nutzer als Grenze angenommen, und von der Lücke der Pfadebene bleibt nur der Rest Grenze, den das README nennt. Was jetzt zählt, ist der Betrieb: eine Claude-Code-Sitzung über mehrere Token-Refreshes des Hosts ohne „no mapping table“ im Log, und daneben die Felder `unknown` und `unknown_hits` im Log des Rückwegs, die zählen, wie oft das Modell Tokens in Pseudonymform ohne Tabellenzeile schreibt, erfundene Namen und verrutschte Ziffern; mit ihren Zahlen wird die Länge der Pseudonyme wieder aufgemacht, zwölf Hexziffern gegen kürzere Formen.
