# Befunde aus dem Testlabor

Von vierundzwanzig Befunden sind dreiundzwanzig behoben; der offene, die Lücke im Netz der Pfadebene, ist zum größeren Teil geschlossen: die Pfadebene erkennt bloße Pfade an ihrer Form, offen bleiben der bloße Verzeichnispfad ohne Datei, der Diff-Kopf, Adressen und Windows, und die stehen im README als Grenze. Der zwanzigste kam aus dem Betrieb: das kodierte Leerzeichen eines Markdown-Links machte ein Verzeichnis für das Modell undurchsichtig, behoben mit `c769892`. Der einundzwanzigste auch: das wörtliche Leerzeichen eines Verzeichnisnamens beendete den Pfad, und alles dahinter ging im Klartext hinaus, behoben mit `db0a173`. Die drei danach kamen aus einem Fehlerbericht vom 2. Oktober, der dieselben Namen in einer Sitzung mal ersetzt und mal im Klartext sah: der bloße Pfad in Anführungszeichen, den `git status` für einen Namen mit Leerzeichen schreibt, endete am Leerzeichen (`3228fd5`, `6a95bee`), das Vorzeichen einer Diff-Zeile klebte am Pfad (`e39435c`), und ein versteckter Name am Ende eines bloßen Pfades zählte nicht als Form (`9d14e5a`). Als Grenze angenommen ist auch die Versalschrift mit SS. Das einzelne Surrogat im Stream bleibt als Abwägung stehen. Die zwei Befunde, die eine Kommandozeile verfälschen konnten, sind schärfer kuriert als vorgeschlagen: der Lader weist einen Wert mit Sonderzeichen beim Start ab und nennt die Zeile, statt nur zu warnen, eine Entscheidung des Nutzers. Die zehn Tests des Pakets `harm` bleiben rot und überspringen sich weiter, denn sie zeigen die Wirkung eines Wertes, den der Lader nicht mehr durchlässt; sie sind Dokumentation, keine Forderung. Die Kuren, in der Reihenfolge des nächsten Kapitels: die sieben von je einer Zeile, die drei Lecks mit Entscheidung, die Schlüsselnamen und doppelten Schlüssel im JSON mit dem gemeinsamen Scanner, die Verfälschungen im Stream, und die Härtung: Wortgrenzen für Regex-Terme, Adressmuster in Zahlenketten, verklebte Ersatzwerte, der Netz-Term mit kaputtem Platzhalter und die fünf Prüfungen an der Konfiguration. Die Kapitel dazu sind stehen geblieben und tragen den Vermerk, womit sie behoben wurden; das offene trägt wie zuvor seinen Test und den Vorschlag. Jedes Kapitel nennt Ursache, Fundort, Reproduktion und Vorschlag genau genug, dass eine andere Sitzung sie abarbeiten kann, ohne diese hier gelesen zu haben; die Reihenfolge steht im nächsten Kapitel.

Die Tests liegen im Repository. `internal/testlab/` trägt sie in fünf Paketen — `basics`, `layers`, `harm`, `props`, `config` — samt dem gemeinsamen Helfer `lab`; die Proben der JSON-Ebene stehen neben `payload`, die des Streams im Wurzelpaket neben `stream.go`. Gegen dieses laufen sie jetzt wirklich: der Nachbau, den das Labor brauchte, solange es ein eigenes Modul neben dem Klon war, ist weg, und siebzehn der neunzehn Stream-Proben halten gegen das Original genau so wie gegen den Nachbau.

Ausführen mit `go test ./...`; die Suite ist grün. Die zehn Tests des Pakets `harm`, die zeigen, was ein Wert mit Sonderzeichen anrichtet, überspringen sich selbst und sagen es. Wer sie fallen sehen will, setzt eine Umgebungsvariable:

	PRIVACYFILTER_OPEN_FINDINGS=1 go test ./...

Wer einen Befund kuriert, streicht in seinem Test den Aufruf von `skipOpenFinding` und sieht ihn grün werden. Von den rund 400 Testfunktionen des Moduls decken die übrigen Round-Trip, Tokengrenzen, Idempotenz in beide Richtungen, überlappende Terme, Regex-Metazeichen als Literale, die Zahlenschreibweise, die Verschachtelungstiefe bis 5000 Ebenen, den SSE-Parser mit CRLF und ohne Leerzeichen nach `data:`, die doppelte Kodierung in `partial_json` mit Anführungszeichen, Backslash und Emoji sowie Bodies mit umgebendem Leerraum ab. Dazu die Formen des Systembetriebs: derselbe Rechnername in dreizehn Befehlszeilen, Adressen mit Port, Präfixlänge und IPv6-Klammern, Konfigurationszeilen in YAML, INI, JSON, systemd und `/etc/hosts`. Dazu der Alltag einer Sitzung: ein Patch, der hinterher noch passt, ein Fragment als `old_string`, Compilermeldungen mit Zeile und Spalte, und die Frage, was von einem Ersatzwert übrig bleibt, wenn das Modell ihn nicht wörtlich wiederholt. Dazu die Sperrliste an einem Body in der Gestalt des echten, sechzehn Schreibweisen eines Pfades, der Namensraum unter Kollisionsdruck und die Ableitung des Salts. Und schließlich zehn Fuzz-Ziele mit Korpus, Nebenläufigkeit und Maßstab.

Eine Warnung zur Arbeitsweise an diesen Dateien: jede von ihnen läuft auf ihrem Weg auf die Platte selbst durch den Filter. Eine Adresse, die als Literal im Quelltext steht, kann dort als etwas anderes ankommen, und aus einer Ausgabe kopierte Werte sind Ersatzwerte, keine Beispiele. Werte, auf die es ankommt, deshalb zur Laufzeit aus Zahlen zusammensetzen, wie es `ranges_test.go` und `v4` neben `payload` tun; nur so ist die Probe das, was sie zu sein vorgibt. Beim Verschieben ganzer Dateien hilft `cp`: was nie durch das Modell läuft, kann auch nicht verfälscht ankommen.

---

# Reihenfolge der Kuren

Was vor dem produktiven Einsatz weg musste, war nicht die längste Liste, sondern die kurze: nur zwei Befunde konnten aktiv Schaden anrichten, und beide stehen im Kapitel über die Sonderzeichen im Originalwert. Ein Wagenrücklauf zeigt in der Rückfrage einen anderen Befehl an, als ausgeführt wird, und ein Zeilenumbruch oder ein Semikolon im Wert verwandelt eine Zeile in zwei. Seit `65202b0` zählt der Lader solche Werte und warnt; die Liste auf dem Server ist daraufhin durchgesehen und enthält keinen. Alles andere in diesem Bericht ließ Daten hinaus oder verlor Text — schlimm genug, aber es zerstörte nichts auf einem Server.

Die sieben Kuren von je einer Zeile sind erledigt und liegen in drei Commits. `8e1bbb7` bindet die Sperrliste an den Ort statt an den Schlüsselnamen: `signature` hängt jetzt am Blocktyp, unterhalb der Argumente eines Werkzeugaufrufs gilt keine Regel mehr, ein gepunkteter Eintrag wird elementweise verglichen, und die Felder, die der Anbieter wörtlich braucht, stehen in der Liste — `container`, das Zugangsdatum eines MCP-Servers, `tool_choice`, `mcp_servers`, `input_schema.required`, `stop_sequences`, `betas` und die Signatur im Stream-Delta. `4d5f2e3` bringt dem Lader der Term-Liste bei, ein Doppelkreuz nur dort als Kommentar zu lesen, wo es eines sein kann, und ein vorangestelltes Byte Order Mark abzuwerfen. `d9821d0` prüft die Endung eines Dateinamens auf ihre Form, statt sie zu behalten. Jede Kur hat ihren Test, und kein grüner ist dabei gekippt.

Die drei Lecks, die eine Entscheidung brauchten, sind mit `031f72b` erledigt, und zwar anders als hier zuerst vorgeschlagen. Der Ersatzraum wurde nicht verengt, denn das hätte die Ersatzwerte bestehender Sitzungen geändert und die Kollision nur verkleinert; stattdessen urteilt das Exclude nach der Tabelle des Gesprächs, was die Kollision ganz löst und den Weg über die Abschirmung gleich mit. Damit das trägt, ist die Tabelle an das Gespräch gebunden, was den Ersatzwert im Verlauf und die Frist der Tabelle erledigt. Der Teiltreffer ist wie vorgeschlagen durch die Verallgemeinerung der Vorschicht kuriert. Die Schlüsselnamen im JSON, die aufwendigste der drei, hat `4947e0d` erledigt, indem der Hinweg den Byte-Scanner des Rückwegs übernahm; damit fielen die doppelten Schlüssel und das einzelne Surrogat im Body gleich mit.

Die Verfälschungen im Stream hat `6693fec` erledigt: der Rückhalt wird beim Fehlerereignis ausgespült, ein vollständiger Ersatzwert am Fragmentende bleibt zurück, bis das nächste Zeichen da ist, und ein unlesbares Ereignis geht allein durch, ohne den Chunk zu kippen. Die Härtung folgte mit `65202b0`: Wortgrenzen für Regex-Terme, die Prüfung des Zeichens vor und nach einem Adresstreffer, die Wiederherstellung verklebter Ersatzwerte als Kette, das opake Token für den Netz-Term mit kaputtem Platzhalter, die Rechte und der absolute Pfad der Schlüsseldatei, die Mindestlänge im Generator, die Zeilennummer und das Vokabular in der Meldung über eine falsche Art, und die Warnung vor Termen mit Sonderzeichen. Den Eintrag in `path.preserve`, der nie treffen kann, weist `4c28d16` zurück.

Was bleibt, ist entschieden: vom Netz der Pfadebene bleibt der Rest offen, den das README nennt, weil eine noch breitere Regel Fehlalarme in Werkzeugausgaben kauft und die Term-Ebene das eingetragene Verzeichnis ohnehin überall findet; die Versalschrift mit SS bleibt, weil Versalzeilen im Verkehr des Nutzers nicht vorkommen. Beides steht im README unter den bekannten Grenzen, damit ein Nutzer es weiß, bevor er sich auf das Netz verlässt.

---

# Ein Teiltreffer hebelt das Sicherheitsnetz aus

Liegt ein Treffer einer früheren Schicht ganz innerhalb eines Treffers einer späteren, gewinnt der kürzere und der Rest des längeren bleibt im Klartext stehen. Ein Term, der nur einen Teil eines Verzeichnisnamens trifft, verhindert damit, dass die Pfadebene das ganze Segment ersetzt: aus einem Verzeichnis, das nach Kunde und Vorgang benannt ist, geht der Vorgangsteil hinaus. Dasselbe innerhalb einer Adresse, eines Netzes, einer URL, einer IBAN und eines Fingerabdrucks — der Term bricht sie auf und ihr Schwanz bleibt sichtbar.

Die Folge ist paradox und deshalb leicht zu übersehen: ein Eintrag in der Term-Liste macht den Schutz schlechter, als hätte man ihn weggelassen. Wer „kunde“ einträgt, verliert den Schutz für „kundenakte-4711“, den die Pfadebene mit `replace_unknown` von sich aus geboten hätte.

Der zweite Weg dorthin führt über die Abschirmung. Ein ausgeschlossener Treffer — eine Adresse in Ersatzwertform, die das Composite bewusst nicht anfasst — schirmt seine Stelle gegen spätere Schichten ab, und das ist richtig so. Steckt er aber in einem längeren Token, schirmt er das ganze Token mit ab: ein Verzeichnis, das nach Kunde und Knotenadresse benannt ist, wird nicht ersetzt, weil die Adresse darin für einen Ersatzwert gehalten wird. Mit dem Kapitel über die Ersatzadressen zusammen wird daraus ein Weg, auf dem ein Tailscale-Netz die Pfadebene stilllegt.

Für Mailadressen war die Regel im Klon zuerst gelöst: eine Vorschicht `promoteAddresses` ließ die umschließende Adresse gewinnen, beschränkt auf `KindEmail`.

Reproduktion: `TestLayers_TermInsideAnUnknownSegmentUncoversTheRest`, `TestLayers_TermInsideAnAddressBreaksItApart` und `TestLayers_AnExcludedHitShieldsTheSegmentAroundIt`, alle drei rot. `TestLayers_EarlierLayerWinsOverTheLongerLaterMatch` und `TestLayers_PromotionIsLimitedToMailAddresses` hielten die geltende Regel und die Grenze der bestehenden Lösung grün fest.

Vorschlag: die Regel aus `promoteAddresses` von `KindEmail` auf jeden Treffer verallgemeinern, der einen nicht ausgeschlossenen Treffer einer früheren Schicht ganz enthält — der umschließende gewinnt, der ausgeschlossene schirmt weiter ab. Den zweiten Weg löst nicht die Abschirmung, sondern der engere Ersatzraum aus dem Kapitel über die Ersatzadressen; eine Kur deckt dann beide.

Behoben mit `031f72b`. Die Vorschicht heißt jetzt `promoteContaining` und gilt für jede Art, mit vier Ausnahmen: ein Treffer über genau derselben Spanne wird nicht befördert, damit die frühere Schicht die Art bestimmt; ein ausgeschlossener innerer Treffer befördert nicht, weil der Wert um ihn schon die eigene Ausgabe ist; ein Treffer der Art `secret` wird nie befördert, weil die Zugangsdaten-Regeln lose Spannen wie „Host-Key <fingerprint>. “ schneiden und ein opakes Token dem Modell nähme, was die Art des inneren Treffers bewahrt; und der umschließende Treffer muss selbst auf Tokengrenzen stehen. Den zweiten Weg schließt nicht der engere Raum, sondern das tabellengebundene Exclude aus dem nächsten Kapitel: eine echte Adresse ist kein Ersatzwert der Tabelle und schirmt nichts ab. Die drei roten Tests sind grün; `TestLayers_EarlierLayerWinsOverTheLongerLaterMatch` hält jetzt die Beförderung fest, `TestLayers_PromotionHoldsForEveryKind` und `TestLayers_SameSpanKeepsTheKindOfTheTerm` die Grenzen.

---

# Ein Wert als JSON-Schlüssel geht unberührt hinaus

Der Rundgang durch den Body besucht Werte, nie Schlüsselnamen. Steht ein Rechnername, ein Kundenname oder ein Pfad als Schlüssel, geht er im Klartext hinaus. Das ist keine ausgedachte Form, sondern die Form, in der Werkzeuge antworten: `docker inspect` schlüsselt nach Container- und Netzwerknamen, `kubectl get -o json` nach Ressourcennamen, `terraform show -json` nach Adressen der Ressourcen, eine `package.json` nach Paketnamen, jede Zuordnung von Rechner zu Zustand nach dem Rechner.

Die Rückrichtung ist genauso betroffen, und dort wird der Schaden lokal. Schreibt das Modell einen Ersatzwert als Schlüssel — in den Argumenten eines Werkzeugaufrufs etwa, `{"files":{"<Ersatzwert>":"Inhalt"}}` —, wird er nicht wiederhergestellt, und das Werkzeug arbeitet mit dem Ersatzwert weiter. Das ist derselbe Weg, auf dem gestern eine Datei unter einem Ersatznamen entstand, nur eine Ebene tiefer.

Reproduktion: `TestJSONEdge_ObjectKeysAreNeverVisited`, rot, mit beiden Richtungen als Unterprobe.

Vorschlag: Schlüsselnamen auf dem Hinweg wie Werte behandeln und auf dem Rückweg wie Werte wiederherstellen. Das ist mehr als eine Zeile, weil ein Schlüssel Struktur trägt und ein Umbenennen zwei Schlüssel zusammenfallen lassen kann; die Ersatzwerte sind aber injektiv, solange die Tabelle es ist, und der Fall zweier Werte, die auf denselben Ersatzwert fallen, ist bereits ausgeschlossen. Wer den Aufwand nicht will, deckt zumindest die Argumente von Werkzeugaufrufen ab, weil dort der lokale Schaden entsteht.

Behoben mit `4947e0d`, in der engeren Fassung: unterhalb der `input` eines Werkzeugblocks bietet der Rundgang jeden Schlüssel dem Besucher an, in beiden Richtungen, denn dort gehören die Schlüssel dem Werkzeug. Überall sonst bleibt ein Schlüssel ein Wort des Schemas. Möglich wurde das, weil der Hinweg nicht mehr über eine Map geht, sondern über den Byte-Scanner des Rückwegs, der einen Schlüssel als Spanne im Body kennt und an Ort und Stelle ersetzen kann. Der Test heißt weiter `TestJSONEdge_ObjectKeysAreNeverVisited` und behauptet jetzt das Gegenteil seines Namens für die Argumente eines Werkzeugs; `TestJSONEdge_BothDirectionsSeeTheSameFields` hält fest, dass beide Richtungen dieselben Stellen anbieten.

---

# Wo die Ersatzadressen wohnen, wohnen auch echte

Der Ersatzwert für eine IPv4-Adresse liegt in 100.64.0.0/10, der für eine MAC beginnt mit `02`. Beide Räume sind in Betrieb. Aus 100.64.0.0/10 geben Tailscale und Headscale ihren Knoten die Adressen, und Provider teilen daraus ihren Kunden hinter CGNAT zu; mit `02` beginnt jede MAC, die Docker einem Container und seiner Brücke gibt. Der Schutz gegen doppelte Ersetzung prüft allein die Form: `Generator.IsPseudonym` bejaht jede Adresse aus diesem Bereich, gleich ob sie aus der Tabelle stammt oder aus dem Netz des Nutzers, und das Composite reicht sie daraufhin unverändert durch.

Für einen Selbsthoster mit Tailscale ist das der schwerste Befund des Labors: die Adressen seiner eigenen Knoten sind genau die, die er schützen will, und genau die, die der Filter für seine eigenen hält. Für jede `docker inspect`-Ausgabe gilt dasselbe.

Bei IPv6 ist es anders und richtig gelöst. Die Ersatzadressen liegen unter einem festen 48-Bit-Präfix im ULA-Bereich, und geprüft wird dieses Präfix, nicht der ganze Bereich; eine gewöhnliche ULA-Adresse aus einem Heimnetz wird deshalb ersetzt. Was für IPv6 gilt, fehlt für IPv4 und für MAC.

Reproduktion: `TestRange_RealValuesInsideThePseudonymSpace`, rot für Tailscale-Knoten, CGNAT-Adresse und Docker-MAC, grün für ULA und für eine gewöhnliche private Adresse.

Vorschlag: den Ersatzraum verengen, wie bei IPv6 schon geschehen — ein festes /16 innerhalb 100.64.0.0/10 und ein festes 24-Bit-Präfix für MAC senken die Kollision von allem auf ein Tausendstel, ohne die Formtreue anzutasten. Das Exclude stattdessen an die Tabelle zu binden, löst die Kollision ganz, nimmt aber den Schutz für Pseudonyme aus früheren Anfragen desselben Gesprächs, deren Tabelle abgelaufen ist: die würden ein zweites Mal ersetzt und wären auf dem Rückweg nicht mehr aufzulösen. Deshalb zuerst der engere Raum, und ein Konfigurationsschlüssel für den, dessen Netz dennoch hineinragt.

Behoben mit `031f72b`, auf dem zweiten Weg: das Exclude ist `Table.Knows`, und der Einwand gegen diesen Weg fällt weg, seit die Tabelle dem Gespräch gehört statt der Anfrage und ihre Frist ab der letzten Nutzung läuft. Ein Ersatzwert einer früheren Anfrage steht in derselben Tabelle und wird nicht ein zweites Mal ersetzt; eine echte Adresse aus 100.64.0.0/10 steht nicht darin und wird ersetzt. Damit nicht derselbe Wert in zwei Bedeutungen in einem Text steht, gibt die Tabelle nie einen Ersatzwert heraus, der einem ihrer Originale oder einem Literal der Term-Liste gleicht; der Versuchszähler geht daran vorbei wie an einer Kollision. Der Ersatzraum ist unverändert, bestehende Sitzungen behalten ihre Ersatzwerte. Die Ablehnung eines Terms in Ersatzwertform beim Laden ist gefallen, bis auf einen Fall: ein `cidr`-Term, der den ganzen Bereich umfasst, könnte nur auf sich selbst abgebildet werden und wird weiter abgewiesen. `TestRange_RealValuesInsideThePseudonymSpace` ist grün, `TestBuildPlugin_TermInThePseudonymRangeIsReplaced` hält die Ersetzung solcher Terme und die eine Ablehnung fest.

---

# Die Endung eines Dateinamens bleibt stehen, was auch darin steht

Der Ersatzwert für einen Dateinamen behält die Endung, damit das Modell weiterhin sieht, womit es zu tun hat. Als Endung gilt alles hinter dem letzten Punkt. Trägt ein Dateiname dort keine Endung, sondern einen Kundennamen oder eine Vorgangsnummer, geht sie unberührt hinaus: aus einem Bericht, der nach der Firma benannt ist, wird ein Ersatzwert mit der Firma daran, und aus einem Export mit Projektnummer ein Ersatzwert mit der Projektnummer.

Reproduktion: `TestHarm_FileNamePseudonymCarriesTheSuffix`, rot, mit einer gewöhnlichen Endung als grüner Gegenprobe.

Vorschlag: nur behalten, was als Dateiendung durchgeht — höchstens fünf Zeichen, nur Buchstaben und Ziffern, keine Unterstriche, kein Bindestrich —, und alles andere mitersetzen. Wer es genauer will, prüft gegen eine Liste der Endungen, die im Alltag vorkommen; die Prüfung nach Form deckt die Fälle ab, auf die es ankommt.

Behoben mit `d9821d0`, genau so: `maxExtLen` steht bei einem Punkt und fünf Bytes, und der Zeichensatz kennt nur noch Buchstaben und Ziffern. Der Test ist grün. Was bleibt, ist die Endung, die kurz, alphanumerisch und trotzdem vertraulich ist — `.ACME` ist von `.JPEG` der Form nach nicht zu unterscheiden. Das schlösse nur eine Liste bekannter Endungen, um den Preis, dass jede unbekannte Endung wegfällt.

---

# Die Term-Liste verliert Werte beim Laden

Zwei Stellen, an denen ein Term als etwas anderes ankommt, als er in der Datei steht, und beide enden im Klartext.

`termsfile.go:73` schneidet jede Zeile am ersten `#` ab, solange sie nicht mit `{` beginnt. Ein Wert mit Doppelkreuz wird damit halbiert: aus `Projekt#42` wird der Term `Projekt`, und `#42` steht danach ungeschützt im Text. Doppelkreuze kommen in Projekt- und Vorgangsnummern, in Raumbezeichnungen und in Verzeichnisnamen vor. Ein Kommentarzeichen braucht die Datei, aber es sollte nur am Zeilenanfang gelten oder durch `\#` aufhebbar sein.

Die zweite Stelle ist das Byte Order Mark. `strings.TrimSpace` entfernt U+FEFF nicht, weil es kein Leerraumzeichen ist. Wer die Liste unter Windows oder mit einem Editor pflegt, der eine Signatur schreibt, hat als ersten Term eine Zeichenkette, die auf nichts passt — und merkt es nicht, weil nichts protokolliert wird. Ein `strings.TrimPrefix` auf das erste Byte-Tripel der Datei genügt.

Reproduktion: `TestTerm_TruncatedAtHash` und `TestTerm_ByteOrderMark`. Der Lader selbst liegt in `package main` und ist von außen nicht ladbar; die Tests zeigen die Wirkung auf der Detektorebene, die Ursache steht in der genannten Zeile.

Behoben mit `4d5f2e3`. Ein Doppelkreuz öffnet einen Kommentar nur noch am Zeilenanfang oder hinter einem Leerzeichen, eine Zeile in der YAML-Form behält ihres, und ein vorangestelltes Byte Order Mark fällt weg. Die zwei genannten Tests bilden den alten Lader nach und sind damit gegenstandslos geworden; sie sind entfallen. An ihre Stelle treten `TestParseTermsFile_HashInsideAValue` und `TestParseTermsFile_ByteOrderMark` neben `termsfile.go`, die den Lader selbst prüfen, weil sie im selben Paket liegen.

---

# Ein Ersatzwert im Gesprächsverlauf ist für immer einer

Kommt ein Ersatzwert einmal unaufgelöst beim Client an, wird er dort gewöhnlicher Text, und von da an gibt es keinen Weg zurück. Der Hinweg der nächsten Anfrage überspringt ihn, weil das Composite alles ausschließt, was wie ein Ersatzwert aussieht; er wird also nicht in die neue Tabelle eingetragen; also findet der Rückweg nichts, womit er ihn auflösen könnte. Der Fehler nährt sich selbst, und er wächst mit jeder Anfrage, in der das Modell den Wert wiederholt.

Das ist keine Theorie. In dieser Sitzung schlug ein Befehl fehl, weil an der Stelle eines Verzeichnisnamens ein Ersatzwert stand; dieselbe Ursache steckt hinter der Datei, die gestern unter einem Ersatznamen angelegt wurde. Der lokale Schaden ist größer als der entfernte: was das Modell schreibt, wird ausgeführt und auf die Platte geschrieben.

In den Verlauf gerät ein Ersatzwert auf drei Wegen, und alle drei sind in diesem Labor belegt: die Tabelle ist abgelaufen oder verdrängt, das Modell hat den Ersatzwert verändert — gekürzt, umbrochen, mit einem Leerzeichen versehen —, oder der Wert kam in der aktuellen Anfrage nur als Ersatzwert vor und nirgends im Klartext.

Reproduktion: `TestCarry_PseudonymInTheHistoryIsNotResolvable` zeigt die leere zweite Tabelle und den Ersatzwert, der beim Client ankommt; `TestCarry_WaysIntoTheHistory` hält die drei Wege fest, `TestCarry_SameTableStillResolves` die Gegenprobe.

Vorschlag: die Zuordnung an die Sitzung binden statt an die Anfrage. Der Salt ist ohnehin pro Gespräch abgeleitet und die Erzeugung deterministisch; eine Tabelle, die für die Dauer der Sitzung lebt und beim Rückweg konsultiert wird, löst alle drei Wege auf einmal und macht die Frist aus dem übernächsten Kapitel gleich mit erledigt. Der Preis ist Speicher, den der Maßstab-Abschnitt beziffert, und eine Antwort auf die Frage, wann eine Sitzung endet.

Behoben mit `031f72b`. Der Store führt eine Tabelle pro Sitzungskennung, die jede Anfrage des Gesprächs mit `Open` holt und mit `Bind` an ihre `RequestID` knüpft; der Rückweg findet über die `RequestID` die Tabelle des Gesprächs, der Abschluss löst nur die Bindung. Eine Sitzung endet, wenn sie `mapping_ttl` lang nicht benutzt wurde, und jede Anfrage, Antwort und jeder Chunk zählt als Nutzung. Der Restorer ist ein lebender Griff, dessen Suchbaum neu gebaut wird, sobald Zeilen dazukamen; das Einfrieren beim ersten Aufruf ist weg, und `TestRestorer_LaterEntriesAreSeen` hält das fest. Von den drei Wegen ist der erste geschlossen; ein vom Modell veränderter oder in Ersatzwertform erfundener Wert steht weiter in keiner Tabelle und geht laut Vertrag unverändert zum Client. Das Prüfprotokoll listet unter `map` die Zeilen, die eine Anfrage hinzugefügt hat, und unter `restored` die Rückersetzungen dieser Anfrage; der Kopf trägt zusätzlich `table=` mit der Größe der Gesprächstabelle. `TestCarry_PseudonymInTheHistoryIsNotResolvable` ist grün und hält die alte Regel als Gegenprobe an einer frischen Tabelle fest.

---

# Der Schlüssel signature sperrt mehr als den Denkblock

`signature` steht als Schlüsselname in der Sperrliste, unabhängig davon, in welchem Block er auftaucht. Gemeint ist die Signatur des Denkblocks, die an Text und Gesprächspräfix gebunden ist und deshalb unangetastet bleiben muss. Getroffen wird jedes Feld dieses Namens: die Fußzeile, die ein Mail-Werkzeug unter `signature` zurückgibt, die Zeile `Good signature from …` aus einer Commit-Prüfung, ein PDF-Feld. Was dort steht, geht ungefiltert hinaus.

Reproduktion: `TestDeny_SignatureOutsideThinking`, rot für die drei Fremdverwendungen, grün für die Signatur im Denkblock, die unangetastet bleiben muss.

Vorschlag: `signature` an den Blocktyp binden, so wie `name` schon an `ToolNameParents` gebunden ist — gesperrt innerhalb eines Blocks mit `type: thinking` oder `redacted_thinking`, sichtbar überall sonst. Die Sperrliste hat die Maschinerie dafür bereits.

Behoben mit `8e1bbb7`: der Schlüsselname ist aus `Keys` verschwunden, die Teilbaum-Regel deckt die Signatur im Denkblock ohnehin ab. Dazu kamen zwei Einträge, die das Original nur im Stream betreffen: `thinking_delta` und `signature_delta` gelten jetzt als Blocktypen, damit auch ein Bruchstück eines Denkblocks in keiner Richtung angefasst wird, und `delta.signature` steht als Pfad in der Liste.

---

# Das Netz der Pfadebene greift nur bei absoluten Pfaden

Die Pfadebene mit `replace_unknown` ist das Sicherheitsnetz für das Verzeichnis, das niemand in die Term-Liste eingetragen hat. Sie greift bei absoluten Pfaden, bei `./` und bei `~/`. Sie greift nicht beim relativen Pfad ohne führenden Punkt, und das ist die Schreibweise, in der Werkzeuge ihre Ausgaben machen: `git status`, `go build`, jede Compilermeldung. Ebenso wenig bei `$HOME/…`, bei Windows-Pfaden mit Rückstrich, bei UNC-Pfaden und bei Pfaden in `file://`- und `http://`-Adressen.

Für ein Verzeichnis, das in der Term-Liste steht, ist das folgenlos — die Term-Ebene findet es in jeder Schreibweise. Die Lücken zählen genau dort, wo das Netz gebraucht wird, nämlich beim vergessenen Eintrag.

Reproduktion: `TestPath_NetGapsForUnknownDirectories` führt achtzehn Schreibweisen vor und benennt die neun, die durchgehen; `TestPaths_BareShapes` in `detect` hält Fang und Verschonung Form für Form fest. `TestPath_ShapesRoundTrip` zeigt, dass die erkannten Formen sauber zurückkommen, doppelte Schrägstriche und Umlaute eingeschlossen.

Vorschlag: den relativen Pfad ohne Punkt aufnehmen, sobald er mindestens einen Schrägstrich und ein bekanntes Endsegment hat, und die Pfade in `file://`-Adressen mitnehmen. Windows und UNC sind eine Frage der Zielgruppe. Dass ein Verzeichnisname als bloßes Wort im Fließtext stehen bleibt, ist dagegen richtig so: dafür ist die Term-Ebene da.

Behoben mit `421b980`, bis auf einen Rest: die Pfadebene erkennt einen Pfad an seiner Form. Anker sind Schrägstrich, `~/`, `./`, `../`, `$NAME/` und `${NAME}/`; ein bloßes Token mit Schrägstrichen zählt als Pfad, wenn das letzte Segment eine Endung oder einen Schrägstrich am Ende trägt, das erste mit einem Punkt beginnt oder ein Segment ein plattgedrücktes Arbeitsverzeichnis ist, wie Claude Code seine Transkriptordner benennt: ein einzelner Bindestrich, eine Wurzel aus einer festen Liste und mindestens zwei weitere Teile, was auch ohne Schrägstrich allein zählt. Ausgenommen sind ein Punkt im Inneren des ersten Segments, denn so sehen Host- und Modulpfade aus, ein einbuchstabiges erstes Segment wie in `s/x/y/`, `a/` im Diff und `I/O`, `@scope`, `//` und alles hinter `://`. Der Rest ist als Grenze angenommen und steht im README: der bloße Verzeichnispfad ohne Datei und ohne Schrägstrich am Ende, der Diff-Kopf, `file://` und `http://`, Windows und UNC, das versteckte Verzeichnis mit Punkt im Namen und das plattgedrückte Verzeichnis direkt unter der Wurzel. Verworfen sind die Anker allein, weil der Betrieb die Lücke in relativen Pfaden und in den Transkriptnamen vorgeführt hat, die Dreisegmentregel, weil sie `net/http/httptest` und `ja/nein/vielleicht` trifft, und die Sonderbehandlung des Diff-Präfixes, weil die Einbuchstabenregel sie mit erledigt. Der einzige angenommene Fehlfang ist `Input/Output.md`, dessen erstes Wort als Verzeichnis hinausgeht.

---

# Die Sperrliste urteilt nach dem Schlüsselnamen, nicht nach dem Ort

Die Argumente eines Werkzeugaufrufs sind ein freies Objekt: welche Schlüssel darin stehen, bestimmt das Werkzeug, nicht die API. Die Sperrliste prüft aber Schlüsselnamen, wo sie auch stehen. Ein Werkzeug, dessen Argumente `id`, `type`, `model`, `role`, `media_type`, `stop_reason`, `tool_use_id` oder `cache_control` heißen — Namen, die jedes zweite Werkzeug verwendet —, schickt seine Werte im Klartext hinaus. Von elf geprüften Argumenten bot der Rundgang genau eines an; zehn blieben unberührt, weil ihr Schlüssel wie ein Feld des Schemas heißt.

Schärfer wird es beim Blocktyp. Trägt ein Werkzeugargument den Schlüssel `type` mit dem Wert `thinking`, wird das ganze Argumentobjekt für einen Denkblock gehalten und mitsamt seinen Nachbarn ausgenommen. Ein einzelnes Argument schaltet damit den Schutz für die anderen ab.

Und die beiden Richtungen widersprechen sich, wenn ein Objekt zwei `type`-Schlüssel trägt. Der Hinweg liest über den JSON-Dekodierer den letzten, der Rückweg über seinen Byte-Scanner den ersten. Ein Block, der als Text beginnt und als `thinking` endet, wird auf dem Hinweg ausgenommen und auf dem Rückweg als Text behandelt — sein Inhalt geht unberührt hinaus. Doppelte Schlüssel sind nach der Norm undefiniert und im Alltag selten; hier sind sie ein Weg.

Reproduktion: `TestJSONEdge_DenyRulesReachIntoToolArguments`, `TestJSONEdge_ObjectOfOnlyDeniedKeys` und `TestJSONEdge_DuplicateTypeKeyDecidesTheDenyList`, alle rot, dazu `TestJSONEdge_DuplicateKeyInOneObject` für den allgemeinen Fall doppelter Schlüssel, bei dem der Hinweg das erste Paar nie sieht und eine Ersetzung eines der beiden verliert.

Vorschlag: die Sperrregeln an ihren Ort binden, nicht an den Namen. Innerhalb von `tool_use.input` und `tool_result.content` gilt kein Schemafeld, denn dort schreibt das Werkzeug. Für den Blocktyp genügt, ihn nur dort zu lesen, wo ein Block stehen darf — als Element einer `content`-Liste —, und nicht in beliebigen Objekten. Und die beiden Richtungen sollten denselben Schlüssel lesen; welchen, ist zweitrangig, solange es derselbe ist.

Zur Hälfte behoben mit `8e1bbb7`. Unterhalb der `input` eines Werkzeugblocks gilt jetzt keine Regel der Liste mehr, und diese Prüfung steht vor der Teilbaum-Regel, damit ein Argument namens `type` mit dem Wert `thinking` nicht mehr seinen eigenen Teilbaum ausnimmt; `TestJSONEdge_DenyRulesReachIntoToolArguments` ist grün, die Gegenprobe `TestJSONEdge_DenyRulesStillHoldWhereTheyBelong` ebenfalls. Der Inhalt eines `tool_result` behält die Regeln mit Absicht: dort gilt das Schema wirklich, und ein Bild, das ein Werkzeug zurückgibt, trägt seine Bytes unter `source.data` wie jedes andere.

Die doppelten Schlüssel hat `4947e0d` erledigt. Der Hinweg geht über den Byte-Scanner des Rückwegs statt über eine Map: beide Paare werden gesehen und behalten, eine Ersetzung in einem der beiden geht nicht mehr verloren, und der erste `type`-Schlüssel eines Blocks gilt für beide Richtungen. Die drei Tests sind grün, und `TestJSONEdge_ObjectOfOnlyDeniedKeys` zählt die Angebote des Rundgangs unter den Argumenten eines Werkzeugs, wo jeder Schlüssel und jeder Wert eines ist.

---

# Ein Werkzeugname wird an einer Stelle ersetzt und an der anderen nicht

`tools[].name` ist gesperrt, damit das Modell den Namen unverändert sieht. `tool_choice.name` ist es nicht, ebenso nicht die Schlüssel unter `input_schema.properties`, die Einträge in `input_schema.required`, `mcp_servers[].name` und `container`. Enthält ein Werkzeugname einen Term, verweist die Anfrage danach auf ein Werkzeug, das es nicht gibt, und ein Schema verlangt eine Eigenschaft, die es nicht hat. Das ist kein Leck, sondern eine Anfrage, die der Anbieter ablehnt oder falsch beantwortet — und weil `on_error: block` nur den Hinweg schützt, nicht die Stimmigkeit des Bodys, fällt es erst beim Anbieter auf.

Reproduktion: `TestJSONEdge_FieldsTheAPIKnows`, rot, mit der Liste der besuchten Pfade im Protokoll.

Vorschlag: die Sperre von `tools[].name` auf alles ausweiten, was denselben Namen bezeichnet — `tool_choice.name`, `mcp_servers[].name`, `container` —, und die Schlüssel eines `input_schema` samt seiner `required`-Liste unangetastet lassen. Wer Werkzeugnamen schützen will, muss sie überall gleich behandeln; halb ersetzt ist schlechter als beides.

Behoben mit `8e1bbb7`, und etwas weiter gefasst als vorgeschlagen: `tool_choice` und `mcp_servers` sind zu den Eltern des Werkzeugnamens gekommen, `container` und das Zugangsdatum eines MCP-Servers zu den Schlüsseln, `input_schema.required`, `stop_sequences` und `betas` zu den Pfaden. `stop_sequences` steht dabei aus demselben Grund in der Liste wie der Werkzeugname: der Anbieter vergleicht die Zeichenkette wörtlich, ein Ersatzwert würde nie treffen. Die Beschreibung einer Eigenschaft im Schema bleibt Prosa und wird weiter ersetzt.

---

# Der Rückhalt des Streams geht verloren, und einmal geht er doppelt

Zwei Wege, auf denen der zurückgehaltene Text nicht dort landet, wo er soll.

Endet der Stream ohne `content_block_stop` und ohne `message_stop`, wird der Rückhalt nie ausgespült, und der Rest der Antwort erreicht den Client nie. Im Test sind es elf Byte, die Obergrenze liegt bei `MaxPseudonymLen` minus eins. Das trifft die abgerissene Verbindung ebenso wie ein `error`-Ereignis mitten im Stream, und ein `overloaded_error` ist im Betrieb nichts Seltenes. Das Plugin erkennt den Fall und schreibt eine Warnung, kann den Text aber nicht mehr ausliefern, weil der Host am Ende nichts mehr aufruft, in das sich Bytes schreiben ließen.

Der zweite Weg dreht es um. Die Ereignisse eines Chunks werden nacheinander abgearbeitet, und jedes Textstück schiebt seinen Schwanz sofort in den Rückhalt. Scheitert ein späteres Ereignis desselben Chunks, gibt die Verarbeitung einen Fehler zurück, und der Host liefert den Chunk unverändert aus — samt dem ersten Delta, dessen Schwanz schon im Rückhalt liegt. Derselbe Text geht damit zweimal hinaus, einmal roh und einmal aus dem Rückhalt, und der Ersatzwert bleibt in seiner rohen Hälfte beim Nutzer stehen.

Reproduktion: `TestStream_EndWithoutStopEventLosesHeldText` mit der abgerissenen Verbindung und dem Fehlerereignis als Unterproben, und `TestStream_PartialStateThenChunkError`; beide rot. Die Gegenprobe `TestStream_LoneMalformedEventPassesThrough` ist grün, ein einzelnes unlesbares Ereignis ohne vorherigen Rückhalt geht also richtig durch.

Vorschlag: den Rückhalt beim `error`-Ereignis ausspülen, so wie es vor `content_block_stop` und `message_stop` geschieht — das deckt den häufigeren der beiden Abbruchwege ab. Und die Rückhalte eines Chunks erst festschreiben, wenn alle seine Ereignisse durch sind, also auf einer Kopie arbeiten und sie am Ende übernehmen. Für die abgerissene Verbindung bleibt die Warnung, die schon steht.

Behoben mit `6693fec`. Das Fehlerereignis spült den Rückhalt vor sich aus wie die Stop-Ereignisse. Den zweiten Weg schließt eine andere Kur als die vorgeschlagene: ein Ereignis, das sich nicht lesen lässt, geht allein und unverändert durch, mit einer Warnung, und der Chunk läuft weiter, sodass der Schwanz des guten Deltas einmal aus dem Rückhalt kommt statt zweimal. Die Kopie gibt es trotzdem, für den Fall einer Panik in der Verarbeitung: dann wird der Zustand vor dem Chunk wiederhergestellt und der Chunk durchgereicht. Beide Tests sind grün; die abgerissene Verbindung bleibt, wie vorgeschlagen, bei der Warnung.

---

# Nach zehn Minuten ist die Tabelle weg, auch mitten im Stream

Die Frist läuft ab dem Ablegen, nicht ab der letzten Nutzung. Eine Antwort, die länger als zehn Minuten streamt — langes Nachdenken, ein großer Patch, ein zäher Anbieter —, verliert ihre Tabelle mittendrin, und ab dieser Stelle kommt beim Nutzer an, was das Modell geschrieben hat: Ersatzwerte. Kein Datenabfluss, aber der Schaden ist trotzdem handfest, denn was das Modell in eine Datei schreibt, landet dann mit Ersatzwerten auf der Platte.

Reproduktion: `TestStore_TableExpiresWhileTheAnswerRuns` protokolliert den Verlust in Minute zehn, `TestStore_UseRefreshesTheDeadline` zeigt, dass neun Zugriffe die Frist nicht verlängern. Beide sind grün, sie halten das Verhalten fest.

Vorschlag: die Frist beim Zugriff auffrischen, was eine Zeile in `Get` ist, oder sie am Ende des Streams statt am Anfang der Anfrage bemessen. Die Verdrängung bei vollem Speicher hat dieselbe Schlagseite — sie nimmt die zuerst abgelegte Tabelle, und das ist bei einem langen Gespräch die noch laufende —, wiegt aber weniger, weil tausend Tabellen erst einmal zusammenkommen müssen. Immerhin protokolliert das Plugin diesen Fall bereits deutlich.

Behoben mit `031f72b`, zusammen mit der Sitzungstabelle: die Frist läuft ab der letzten Nutzung, und die Verdrängung nimmt die am längsten unbenutzte Tabelle. Die drei Tests behaupten das jetzt statt es zu protokollieren.

---

# Rückhalt hält wachsende Ersatzwerte zurück, entwertete nicht

Endet ein Chunk genau hinter einem vollständigen Ersatzwert und beginnt der nächste mit einem Buchstaben, einer Ziffer oder einem weiteren Ersatzwert, dann ersetzt der Stream, während derselbe Text am Stück unangetastet bleibt. Aus `h-936a9b4f6018` plus `x` wird gestreamt `zeus.lanx`, am Stück richtigerweise `h-936a9b4f6018x`, weil der Ersatzwert dort kein eigenes Token ist.

`Holdback` prüft, ob das Textende der Anfang eines Ersatzwertes sein könnte, also den Fall des Wachsens. Der zweite Fall fehlt: ein bereits vollständiger Ersatzwert am Textende kann durch das nächste Zeichen entwertet werden, und diese Entscheidung lässt sich erst treffen, wenn das Zeichen da ist. Es ist dieselbe Klasse wie der Fehler aus `54545e1`, nur die andere Richtung.

Reproduktion: `TestHoldback_CompletePseudonymAtChunkEnd` mit den Folgezeichen `x`, `1`, `h` und einem weiteren Ersatzwert; `TestHoldback_SplitAtEveryPosition` und `TestHoldback_ByteByByte` zeigen dasselbe beim Zerteilen an jeder Position. Der Gegentest `TestHoldback_DelimiterInNextChunk` ist grün: mit Leerzeichen, Punkt, Komma, Klammer, Zeilenumbruch oder am Textende stimmen beide Wege überein, ebenso beim Unterstrich, der seit `8436b9e` als Grenze gilt.

Vorschlag: endet der Text auf einem vollständigen Ersatzwert, diesen zurückhalten, bis das nächste Zeichen bekannt ist. Der Rückhalt bleibt dabei durch `MaxPseudonymLen` beschränkt, und das Blockende flusht bereits über `flushBefore`. Kein Leck, aber eine Textverfälschung und eine Abweichung zwischen den beiden Wegen, die die Testsuite an anderer Stelle sorgfältig ausschließt.

Behoben mit `6693fec`. Ein vollständiger Ersatzwert, der mit dem Text endet und auf einem Wortzeichen aufhört, bleibt zurück; folgt ein Trennzeichen, wird er sofort restauriert. Der Rückhalt eines Blocks lebt jetzt in `mapping.Tail`, das sich merkt, ob das letzte gelieferte Zeichen ein Wort fortsetzt, damit ein Ersatzwert, der an ein Wort geklebt ist, auch über eine Fragmentgrenze hinweg unangetastet bleibt. Die Schranke `MaxPseudonymLen` gilt weiter, mit einer Ausnahme: eine Kette unmittelbar aufeinanderfolgender Ersatzwerte wird als Ganzes zurückgehalten und als Ganzes restauriert, weil erst ihr Ende zeigt, ob sie eines ist. Die drei Tests sind grün.

---

# Ein Punkt im Schlüsselnamen schaltet die Sperrliste scharf

Der Body `{"metadata.user_id":"flat-value","metadata":{"user_id":"nested-value"},"other":"plain"}` bietet dem Besucher nur `other` an. Der flache Schlüssel, der wörtlich `metadata.user_id` heißt, wird von der Regel für den verschachtelten Pfad erfasst, weil beide zur selben gepunkteten Form zusammengesetzt werden. Sein Wert wird also nie ersetzt und geht im Klartext hinaus.

Das ist der einzige Befund mit Leckwirkung. Sein Gewicht hängt daran, wie wahrscheinlich ein Schlüssel ist, der genau einer Pfadregel entspricht; flache Objekte mit gepunkteten Schlüsseln sind in Konfigurationen und Werkzeug-Argumenten alltäglich, ein Treffer auf `metadata.user_id` ist es nicht. Die Richtung stimmt allerdings ungünstig: die Konfusion führt immer zu mehr Ausschluss, nie zu mehr Ersetzung.

Reproduktion: `TestDeny_DottedKeyConfusion`. Der Gegentest für Teilbaum-Regeln, `TestDeny_DottedKeyConfusionSubtree`, ist grün, und `TestDeny_ToolUseInputName` bestätigt die feine Unterscheidung zwischen `tool_use.name` und `tool_use.input.name`.

Vorschlag: Pfade elementweise vergleichen statt über die zusammengesetzte Form, oder beim Zusammensetzen Punkte im Schlüsselnamen kennzeichnen. Der Fundort ist `DenyList.Denied` in `payload/deny.go`, Abschnitt „Dotted rule“.

Behoben mit `8e1bbb7`: `matchesTail` vergleicht den Eintrag Stück für Stück gegen das Ende des Pfades, und kein Stück darf einen Punkt des Pfades überspannen. Ein einzelner Schlüssel `metadata.user_id` ist damit ein Element und trifft die zweielementige Regel nicht mehr.

---

# Ein einzelnes Surrogat wird zum Ersetzungszeichen

`{"keep":"\ud800","hit":"zeus.lan"}` kommt nach einer Ersetzung als `{"hit":"h-0123456789ab","keep":"�"}` zurück. Ein halbes Surrogatpaar ist gültiges JSON, hat aber keine UTF-8-Kodierung, und der Serialisierer ersetzt es. Ohne Ersetzung im Body passiert nichts, weil `Walk` dann die Originalbytes zurückgibt; sobald irgendwo ein Treffer liegt, wird der ganze Body neu geschrieben und die Stelle stillschweigend verändert.

Solche Sequenzen entstehen, wenn ein Werkzeug Text mitten in einem Zeichen abschneidet und der Client das als JSON kodiert. Selten, aber real, und die Änderung trifft Text, der mit dem Filter nichts zu tun hat.

Reproduktion: `TestWalk_LoneSurrogate`.

Behoben mit `4947e0d` für den Body: der Hinweg kodiert nur noch die Zeichenketten neu, die sich ändern, und jedes andere Byte bleibt, wie es kam, das halbe Surrogat eingeschlossen. Im Stream bleibt der Fall bestehen, denn ein Delta wird als Ganzes neu geschrieben, sobald es einen Rückhalt trägt oder auflöst, und ein halbes Surrogat in einem solchen Delta wird dabei zum Ersetzungszeichen. `TestStream_LoneSurrogateBehindAHoldback` protokolliert das; es ist eine Abwägung, kein Fehler, denn ein halbes Surrogat in einem Modelltext ist kaum je gewollt.

---

# Versalschrift mit SS entkommt der Term-Liste

Ein Term `Straßburger` mit `IgnoreCase` findet `straßburger`, aber nicht `STRASSBURGER`. Das scharfe s hat keine einbuchstabige Großform, und Go faltet die Schreibweisen nicht ineinander. In Versalzeilen — Formularen, Adressblöcken, Ausweisdaten — geht ein Name so im Klartext hinaus.

Reproduktion: `TestUnicode_SharpSCaseFolding`, protokolliert alle drei Schreibungen. Der Test ist bewusst grün, er dokumentiert nur; ob das behoben wird, ist eine Abwägung. Eine Kur wäre, für Terme mit `ß` zusätzlich die `ss`-Schreibung in die Literalsuche aufzunehmen.

Entschieden: es bleibt. Versalzeilen aus Formularen und Ausweisen kommen im Verkehr des Nutzers nicht vor, und wer sie hat, trägt die `SS`-Schreibung als zweiten Term ein; das README sagt es unter den bekannten Grenzen.

---

# Ein Term mit Sonderzeichen kommt als Kommando zurück

Der Ersatzwert ist immer ein harmloses Einzelwort, der Originalwert nicht unbedingt. Das Modell sieht `d-abe950cb6234`, hat keinen Grund zu quotieren und schreibt `ls /mnt/d-abe950cb6234/`. Der Restorer setzt den Originalwert ein, und in der Shell des Nutzers steht `ls /mnt/kunde x & co/` — ein Kommando im Hintergrund und ein zweites hinterher. Dasselbe mit `;`, mit Backtick und mit `$( )`. Quotiert das Modell den Ersatzwert, hilft das gegen diese vier, aber nicht gegen den Apostroph: aus `grep 'A-1234'` wird `grep 'Sean O'Connor'`, und die Anführung kippt.

Es ist kein Leck und auch keine Einschleusung von außen — der Originalwert steht in der Term-Liste des Nutzers, niemand Fremdes bestimmt ihn. Es ist eine Formänderung zwischen dem, was das Modell geschrieben hat, und dem, was ausgeführt wird. Im Normalbetrieb sieht der Nutzer den wiederhergestellten Befehl in der Rückfrage, bevor er läuft; im automatischen Modus sieht er ihn nicht.

Reproduktion: `TestAdmin_UnquotedAliasInCommand` für die unquotierte Stelle, `TestAdmin_TermWithShellMetacharacters` für die quotierte. Beide sind grün, sie halten das Verhalten fest.

Vorschlag: beim Laden der Term-Liste eine Warnung für Werte, die `'`, `"`, Backtick, `$`, `;`, `&`, `|`, `<`, `>`, Zeilenumbruch oder Tabulator enthalten. Kein Startfehler, denn ein solcher Wert kann gewollt sein. Das Leerzeichen bleibt draußen, Personennamen tragen es regulär; dafür genügt ein Satz im README unter „Grenzen“.

Die Kommandozeile ist dabei nur der auffälligste Ort. Der Rückweg schreibt den Originalwert in jeden Text, den der Client weiterverarbeitet, und jedes Zeichen mit Sonderbedeutung wirkt dort, wo es landet. Ein Zeilenumbruch im Wert bricht die Zeile eines Patches, einer Konfigurationsdatei und eines Kommentars auseinander, und aus einem Kommentar wird dabei ausführbarer Text. Ein Wagenrücklauf zeigt in der Rückfrage einen anderen Befehl an, als anschließend ausgeführt wird — die Anzeige überschreibt sich selbst. Ein Doppelkreuz im Wert kürzt eine Konfigurationszeile stillschweigend, ein Prozentzeichen schneidet eine crontab-Zeile ab, ein Schrägstrich legt eine Datei ein Verzeichnis tiefer ab als vorgesehen. Gerät der Wert in ein Suchmuster oder in eine `sed`-Ersetzung, die das Modell gebaut hat, sucht und ersetzt sie etwas anderes; gerät er in JSON, das das Modell geschrieben hat, zerstören Anführungszeichen und Rückstrich den Body.

Diese Fälle teilen eine Ursache und eine Kur: das Modell quotiert nach dem, was es sieht, und der Restorer setzt etwas ein, das anders quotiert werden müsste. Reproduktion im Paket `harm`, zehn rote Tests von zwanzig, jeder für einen Zielkontext. Der Unterschied zum Rest der Familie ist wichtig: der Wagenrücklauf und das Doppelkreuz verstümmeln still, der Zeilenumbruch und der Schrägstrich fallen auf. Still ist schlimmer.

Behoben mit `65202b0` als Warnung mit der Zahl der Werte, wie vorgeschlagen, und mit `c3679d3` auf Entscheidung des Nutzers zur Ablehnung verschärft: der Lader weist einen Wert ab, der ein Anführungszeichen, einen Rückstrich, ein Metazeichen der Shell, ein Doppelkreuz, ein Prozentzeichen, einen Schrägstrich oder ein Steuerzeichen trägt, nennt die Zeile der Term-Datei oder den Index des Eintrags in der `config.yaml`, und schreibt den Wert nicht ins Log. Beurteilt werden nur diese Zeichen; Buchstaben jeder Schrift, chinesische, kyrillische, türkische, gehen durch, ebenso Ziffern, Leerzeichen, Punkte, Bindestriche und Klammern. Der Schrägstrich eines Netzes in CIDR-Form zählt nicht, und ein regulärer Ausdruck wird nicht beurteilt, weil seine Metazeichen ihm gehören; wer einen solchen Wert braucht, schreibt ihn als Ausdruck, der ihn ohne das Zeichen trifft. `TestTermsFile_UnsafeValues` hält die Zeichenklasse fest, `TestTermsFile_UnsafeValueIsRefusedWithTheLine` die Ablehnung mit Zeile. Die zehn roten Tests bleiben rot und überspringen sich weiter, denn sie zeigen die Wirkung eines Wertes, den der Lader nicht durchlässt. Die Liste auf dem Server enthält keinen.

Die Verschärfung trifft ihren eigenen Lieferanten: `machine-ids.py` schreibt das Schlüsselmaterial der SSH-Hostkeys und der eigenen öffentlichen Schlüssel als Terme der Art `secret`, und Base64 führt den Schrägstrich im Alphabet; eine solche Zeile ließe die Registrierung scheitern, und eine Meldung, die jede Klasse aufzählt, liest sich, als wäre ein Rückstrich gefunden worden. Mit `e1cefb8` behält ein `secret` seinen Schrägstrich wie ein Netz in CIDR-Form, denn sein Ersatzwert ist ein opakes `PF_`-Token, das dort steht, wo der Blob stand, nie in einem Pfad; Anführungszeichen, Backtick, Dollar und Steuerzeichen bleiben auch für `secret` verboten, was bei Base64 nichts kostet. Die Meldung nennt die gefundene Klasse, weiter ohne den Wert. `TestTermsFile_UnsafeValues` prüft den Schlüsselblob als `secret` und als `host`, `TestTermsFile_UnsafeValueIsRefusedWithTheLine` die benannte Klasse und das Fehlen des Werts in der Meldung.

Dasselbe gilt für einen `fingerprint`: hinter dem Etikett `SHA256:` stehen 43 Zeichen Base64 mit Schrägstrich. `89ce66d` nimmt `fingerprint` ebenso aus; sein Ersatzwert ist `SHA256:PF` mit Buchstaben und Ziffern und steht dort, wo der Fingerabdruck stand. Der Test prüft auch einen Fingerabdruck mit Schrägstrich. Der Lader beurteilt damit den Schrägstrich in drei Arten nicht: `cidr`, `secret`, `fingerprint`; in jeder anderen Art bleibt er verboten, weil ein Host, ein Segment oder ein Name mit Schrägstrich in einem Pfad landen kann.

Schwerer als jede Zeichenklasse wiegt eine Schwäche der Ablehnung selbst: ein abgebrochener Start ist die schlechteste Form, den Nutzer zu erreichen. Der Host kommt ohne den Filter hoch, schreibt eine Zeile unter tausende ins Log und reicht jede Anfrage im Klartext weiter, bis jemand diese Zeile findet. Zwei Wege standen gegeneinander: die fehlerhafte Zeile überspringen und warnen, womit der eine Wert bei jeder Anfrage hinausgeht und die Warnung wieder nur im Log steht; oder registrieren und sperren. `105fb20` baut den zweiten Weg. Scheitert das Einrichten des Pseudonymize-Modus, fehlender Secret, unlesbare Term-Datei, abgewiesener Term, unerreichbare Schicht, registriert sich das Plugin mit dem Fehler, meldet nur den Anfrage-Interceptor als Fähigkeit und beendet jede Anfrage mit Status 400 und einer Meldung, die Datei, Zeile und Klasse nennt, nie den Wert, bis die Konfiguration repariert und der Proxy neu gestartet ist. Der Nutzer sieht die Meldung bei der ersten Anfrage in seinem Client. Die Skip-Listen gelten dabei nicht, ein Plugin ohne Einrichtung filtert nichts und lässt darum nichts durch. `mode: redact` bricht die Registrierung weiter ab wie das Original. `assertBlocked` in `block_test.go` prüft den Zustand für jeden Startfehler, `TestBlocked_SkipListsDoNotApply` die Skip-Listen; der Weg ist am lebenden System durchgespielt, mit einer absichtlich falschen Zeile in der Term-Datei: Neustart, die Fehlerzeile im Log, die Meldung in Claude Code, dann Zeile weg und Neustart. `TestBlocked_BadTermLineIsReportedInLogAndClient` hält die Plugin-Seite davon fest, über den Test-Hook von logrus: die Fehlerzeile bei der Registrierung mit Zeile und Klasse ohne den Wert, die Warnzeile je gesperrter Anfrage, die Meldung an den Client. Der Parser der Term-Datei nennt bei einem Syntaxfehler die Position des unerwarteten Worts und die Zahl der Wörter, bei der YAML-Form die erwartete Form, nie den Text der Zeile, denn die Meldung erreicht im Sperrzustand den Client; `TestParseTermsFile_Errors` prüft das mit. `v0.4.13-dev` auf dem Server trägt diese Kur nicht.

---

# Regex-Terme und Adressmuster greifen weiter, als sie sollen

Ein Term mit `Regex` statt `Value` wird ohne Wortgrenzen angewandt und trifft deshalb mitten im Token: der Ausdruck ersetzt einen Teil eines längeren Wortes und lässt den Rest stehen — dieselbe Wirkung wie beim Teiltreffer, nur aus der Konfiguration heraus. Wer die Term-Liste mit Ausdrücken pflegt, muss die Grenzen also selbst in den Ausdruck schreiben, und nichts sagt ihm das.

Zwei Terme, die im Text unmittelbar aneinandergrenzen, verkleben ihre Ersatzwerte zu einem Wort. Der Rückweg kann das nicht mehr trennen, weil die Grenze fehlt, an der er ansetzen müsste; der Round-Trip bricht. Gefunden hat das der Fuzz-Lauf, nicht ein ausgedachter Fall.

Die Adressmuster greifen in längere Zahlenketten hinein: eine Folge von Ziffern und Punkten, die vier passende Gruppen enthält, wird als Adresse gemeldet, auch wenn sie Teil einer längeren Kette ist. Das ist die Verwandtschaft der vierstelligen Versionsnummer aus den Beobachtungen, hier aber ohne die Entschuldigung, dass es eine gültige Adresse wäre.

Reproduktion im Paket `props`: `TestProps_RegexTermInsideAToken`, `TestProps_TouchingTermsGlueTheirPseudonyms`, `TestProps_AddressInsideALongerRun` und `TestProps_CidrTermWithABrokenWildcard`, alle rot, dazu drei Fuzz-Ziele mit Korpus. Der Fuzz-Lauf über den Round-Trip hat die verklebten Ersatzwerte selbständig gefunden.

Vorschlag: für Regex-Terme entweder die Wortgrenzen erzwingen oder beim Laden warnen, wenn ein Ausdruck keine trägt. Die verklebten Ersatzwerte lassen sich nur beim Erzeugen lösen — ein Trennzeichen, das im Ersatzwert nicht vorkommt, oder die Weigerung, zwei Treffer ohne Trennzeichen dazwischen beide zu ersetzen. Die Zahlenketten löst eine Prüfung auf das Zeichen vor und nach dem Treffer.

Behoben mit `65202b0`. Ein Treffer eines regulären Ausdrucks unterliegt derselben Wortgrenze wie ein Literal und wird verworfen, wenn er mitten im Token liegt; `TestProps_RegexTermInsideAToken` behauptet jetzt, dass ein solcher Text unverändert hinausgeht. Die verklebten Ersatzwerte sind nicht beim Erzeugen gelöst, sondern beim Auflösen: der Rückweg nimmt einen Ersatzwert, der unmittelbar auf einen anderen folgt, als eigene Ausgabe und restauriert die ganze Kette, denn zwei Ersatzwerte ohne Trennzeichen kann nur der Hinweg geschrieben haben. Ein Ersatzwert, der an ein gewöhnliches Wort geklebt ist, bleibt dagegen unangetastet. Die Adressmuster prüfen das Zeichen vor und nach dem Fenster: steht davor oder dahinter ein weiteres Glied derselben Kette aus Punkten oder Doppelpunkten, ist es keine Adresse. Und ein `cidr`-Term, dessen Adressteil kein vollständiges Viertupel ist, bekommt ein opakes Token statt einer Adressform, die nicht zu ihm passt. Die vier Tests und die drei Fuzz-Ziele sind grün.

---

# Was die Konfiguration stillschweigend annimmt

Fünf Stellen, an denen ein falsch gemeinter Eintrag angenommen wird und nichts tut oder etwas anderes tut als gedacht.

Ein Eintrag in `path.preserve`, der einen Pfad statt eines Segments enthält, wird angenommen und wirkt nie. Alle vier geprüften Formen gehen still durch, mit führendem Schrägstrich, mit abschließendem, mit zwei Segmenten und als Glob. Der Nutzer liest seine eigene Konfiguration, sieht das Verzeichnis dort stehen und wundert sich, dass es weiterhin ersetzt wird. Die Kur ist, solche Einträge in `NewPaths` zurückzuweisen und den Eintrag in der Meldung im Klartext zu nennen.

Die Rechte der Schlüsseldatei sieht sich niemand an. Sie entsteht beim Ausrollen von Hand, ein zu großzügiger Modus fällt an keiner Stelle auf, und aus dem Salt-Schlüssel lassen sich alle Ersatzwerte einer Sitzung nachrechnen. Drei Zeilen über `os.Stat` genügen, um es zu halten wie ssh: bei Leserecht für Gruppe oder andere abbrechen oder mindestens warnen.

Der Pfad des Schlüssels wird relativ, wenn das Plugin-Verzeichnis nicht zu ermitteln ist. Dann fehlt entweder die Datei und die Registrierung bricht mit einem nichtssagenden Pfad ab, oder es liegt zufällig eine im Arbeitsverzeichnis und wird genommen. Ein nicht absolutes Ergebnis sollte zurückgewiesen werden, und der konfigurierte Wert vor dem Auflösen getrimmt.

Die Mindestlänge des Salt-Schlüssels prüft nur der Lader, nicht `NewGenerator`. Im Betrieb hält die Regel, weil `main.go` über den Lader geht; im Vertrag von `NewGenerator` steht sie nicht, und ein künftiger Aufrufer erfährt es nicht.

Die Meldung für eine falsche Art in der Term-Liste nennt keine richtige und zeigt auf einen Index statt auf eine Zeile. Bei einer Datei mit einigen hundert Zeilen muss der Nutzer abzählen. Die erlaubten Arten stehen ohnehin in `Kind.Valid`, und die Zeilennummer kennt der Lader.

Reproduktion im Paket `config`, 32 Proben, davon eine rot: `TestConfig_PathsPreserveEntriesThatCannotMatch`. Die übrigen vier sind grün und protokollieren, weil sie Härtungen betreffen und keine Fehler.

Behoben mit `4c28d16` und `65202b0`. `NewPaths` weist einen Eintrag in `path.preserve` zurück, der einen Schrägstrich oder einen Platzhalter trägt, und nennt ihn in der Meldung. Die Schlüsseldatei muss dem Eigentümer allein lesbar sein, sonst bricht das Laden ab wie bei ssh; ihr Pfad wird vor dem Auflösen getrimmt und muss absolut sein, ein relativer wird zurückgewiesen. Diese Prüfung hat beim ersten Ausrollen die Registrierung gekippt, denn der Host übergibt sein Plugin-Verzeichnis so, wie es in seiner Konfiguration steht, relativ zu seinem Arbeitsverzeichnis; seit `d10f223` macht `buildPlugin` das Verzeichnis einmal absolut, bevor irgendetwas dagegen aufgelöst wird, und `TestBuildPlugin_RelativePluginDirFromTheHost` hält den Fall fest. `NewGenerator` prüft die Mindestlänge selbst über `CheckSecret`. Die Meldung über eine falsche Art nennt die Zeile der Term-Datei und die erlaubten Arten in ihrer Reihenfolge; für einen Eintrag aus der `config.yaml` bleibt es beim Index, denn eine Zeile hat er nicht. Die fünf Proben behaupten das jetzt, statt zu protokollieren.

---

# Ein kodiertes Leerzeichen macht ein Verzeichnis undurchsichtig

Ein Markdown-Link schreibt ein Verzeichnis mit Leerzeichen im Namen URL-kodiert, `Kunden%20Akten`, weil ein bloßes Leerzeichen das Linkziel beendet, und das Prozentzeichen zählt in der Pfadebene zu den Segmentzeichen. Das ganze Segment wurde als ein Wort gehasht, und das Modell sah ein einzelnes `d-<12 hex>` ohne jedes `%20`. Es konnte nicht wissen, dass darin ein Leerzeichen steckt, löste den relativen Link richtig auf, setzte das Pseudonym in einen Dateisystempfad, und der Rückweg stellte daraus wieder `Kunden%20Akten` her: ein Verzeichnis, das es auf der Platte nicht gibt. Das Lesewerkzeug meldete „File does not exist“, und der Nutzer sah einen Pfad, der bis auf das `%20` stimmte.

Gefunden im Betrieb an einem Link dieser Form in einem Notizverzeichnis, dessen Ziel ein Verzeichnis höher lag. Die Sitzung, die den Fehler untersuchte, sah das Segment in der Ausgabe von `grep` wieder nur als Pseudonym; erst ein Längenvergleich des Linksegments mit dem echten Verzeichnisnamen und ein `ls` mit dekodiertem Ziel zeigten die Kodierung.

Reproduktion: `TestPath_EncodedSpaceInALink` im Paket `basics` schickt den Link durch Hin- und Rückweg: zwei Pseudonyme um das `%20`, zurück in beiden Schreibweisen, als Link, wie er war, und als Pfad mit dekodiertem Leerzeichen, und dieselben Pseudonyme für das Verzeichnis, wie ein Werkzeug es mit echtem Leerzeichen auflistet. `TestPaths_EncodedSpaceDividesASegment` in `detect` hält die Teilung Form für Form fest, Dateinamen und leere Wörter eingeschlossen, `TestTerms_WordBoundary` den Term hinter dem Escape, `TestRestorer_TokenBoundary` in `mapping` das Pseudonym dahinter, und `TestHoldback_EncodedSpaceBetweenPseudonyms` schneidet den Stream an jeder Stelle, auch mitten im `%20`.

Gewicht: kein Leck, aber ein Werkzeugaufruf, der ins Leere geht, bei jedem Link auf ein Verzeichnis mit Leerzeichen im Namen, und ein Modell, das den Grund nicht sehen kann, weil der Filter ihn ihm nimmt. Ohne Filter stünde das `%20` im Kontext, und das Modell könnte es ersetzen.

Kur: drei Stellen. Die Pfadebene teilt ein Segment an `%20` in Wörter und meldet jedes für sich; das `%20` bleibt stehen, das Modell sieht `d-…%20d-…`. Die Wörter eines Dateinamens bleiben Dateiname, in Ruhe gelassen wie er, mit `filenames: all` einzeln ersetzt und die Endung am letzten. Dann die Grenzregel: ein Prozent-Escape, Prozentzeichen und zwei Hexziffern, bindet an nichts. `PercentEscapeEnds` in `detect` sagt es, und die Term-Ebene, die Strukturmuster, der Restaurierer und der Zähler der Pseudonymformen fragen es, denn vor dem `d-…` hinter `%20` steht eine Ziffer, die sonst bände, und beim wörtlichen Zitat des Links käme die zweite Hälfte als Pseudonym beim Nutzer an. Im Stream merkt sich der `Tail` statt eines Bits die letzten vier Bytes des gelieferten Textes, damit ein Schnitt mitten im `%20` dieselbe Entscheidung bekommt wie der Text am Stück. Schließlich `SegmentTokens`, damit ein Verzeichnis, das das Modell selbst mit `%20` nennt, Wort für Wort als sein eigenes zählt.

Verworfen: das Segment vor dem Hashen dekodieren und das Dekodierte als Original eintragen, weil dann ein wörtlich zitierter Link mit echtem Leerzeichen zurückkäme und der Round-Trip bräche; und die Teilung an jedem Prozent-Escape, weil ein dekodiertes `%C3%BC` einen Buchstaben direkt an ein Pseudonym klebt, das der Rückweg dann nicht findet, und das Modell aus `d-…%C3%BCd-…` eher einen kaputten Pfad baut als aus einem Pseudonym. Als Grenze bleibt: ein Wort mit einem anderen Escape ist als Ganzes ein Pseudonym; der Link kommt zurück, der dekodierte Pfad nicht, und die Datei ist über ihren Namen zu finden, der lesbar bleibt. Das README nennt es.

Behoben mit `c769892`.

---

# Ein Leerzeichen beendet den Pfad

Die Pfadebene lief über Schrägstriche und Segmentzeichen und endete am ersten anderen Zeichen, also auch am Leerzeichen. Ein Verzeichnis mit Leerzeichen im Namen ging nur bis zum ersten Wort als Pseudonym hinaus; was dahinter stand, war für die Ebene Prosa. Ein Wort ohne Schrägstrich blieb stehen, und ein bloßes Token mit Schrägstrichen galt nur dann als Pfad, wenn sein letztes Segment eine Endung oder einen Schrägstrich am Ende trug. In einem `cd` auf ein Verzeichnis ohne Datei blieb deshalb alles ab dem ersten Leerzeichen im Klartext, die tieferen Verzeichnisse eingeschlossen; in einem `file_path` mit Dateiname fing die Endung den Schwanz wieder ein, und nur die Wörter zwischen dem ersten Leerzeichen und dem letzten Wort des Segments leckten.

Gefunden im Betrieb an einem `cd` in Anführungszeichen auf ein Verzeichnis, dessen Name drei Wörter hat: das erste Wort kam als Pseudonym, die zwei anderen und die drei Verzeichnisse darunter im Klartext. Der Nutzer sah es in der ausgehenden Anfrage.

Reproduktion: `TestPaths_SpaceInsideADirectoryName` in `detect` hält die drei Formen und ihre Grenzen Fall für Fall fest, mit dem, was zwischen den Wörtern stehen bleibt, und mit den Wörtern eines Dateinamens; `TestPath_SpaceInADirectoryName` im Paket `basics` schickt ein `cd` in Anführungszeichen durch Hin- und Rückweg, lässt das Modell den Pfad maskiert und bloß zurückschreiben und prüft, dass alle drei Schreibweisen dieselben Pseudonyme bekommen.

Gewicht: ein Leck. Jeder Verzeichnisname mit Leerzeichen ging ab dem Leerzeichen hinaus, samt allem, was unter ihm liegt, bei jedem Befehl auf ein Verzeichnis ohne Dateinamen; mit `replace_unknown: true` ist das die Lücke, die diese Einstellung schließen soll.

Kur: das wörtliche Leerzeichen wird wie das kodierte behandelt. Jedes Wort des Segments bekommt sein Pseudonym, das Leerzeichen bleibt stehen, und das Modell sieht `d-… d-…`; was es zurückschreibt, zitiert, maskiert oder bloß, restauriert Wort für Wort. Wo der Pfad endet, sagen drei Formen in `continued`. Hinter einem Anführungszeichen, einem doppelten, einem einfachen oder einem Backtick, auch vor einer Shell-Variablen, läuft er bis zum schließenden auf derselben Zeile; `?` und `#` beenden ihn wie außerhalb, und ein Wort mit Endung schließt ihn am nächsten Leerzeichen ab, damit `"x.go: fix the test"` Dateiname und Satz bleibt. Hinter `\ ` läuft er weiter. Im bloßen Pfad läuft er über das Leerzeichen, wenn das nächste Wort einen Schrägstrich im Inneren trägt, kein Pfad für sich ist und das Wort davor weder Endung noch Satzpunkt hat. `segments` nimmt als Wörter die Läufe aus Segmentzeichen; was dazwischen steht, Leerzeichen, Backslash, Kaufmanns-Und, Klammer, bleibt, und ein Wort ohne Buchstabe oder Ziffer wird nicht gemeldet. Rückweg, Stream und Zähler brauchten nichts, Leerzeichen und Backslash waren schon Grenzen.

Verworfen: der ganze Wert als Pfad, sobald er mit einem Pfad beginnt, weil ein Prosawert wie „/etc/hosts prüfen und Eintrag ergänzen“ seine Wörter als Verzeichnisnamen gehasht bekäme; eine Liste von Werkzeugargumenten, die als Ganzes ein Pfad sind, weil unter dem `input` eines Werkzeugs kein Schlüsselname urteilt; und das Weiterlaufen über mehrere Wörter bis zum nächsten mit Schrägstrich, weil „Move detect/paths.go into pkg/detect“ dann ein Pfad wäre. Als Grenze bleibt der bloße Name aus drei Wörtern im ganzen Wert, dessen mittleres stehen bleibt, und der Pfad hinter einer Option in Anführungszeichen, `"--out=/home/alice/Kunden Akten"`, den die Ebene als bloßen liest; als Preis das Schrägstrich-Wort der Prosa direkt hinter einem bloßen Pfad, das als dessen Rest gilt und unverändert zurückkommt. Das README nennt alle drei.

Behoben mit `db0a173`.

---

# Ein bloßer Pfad in Anführungszeichen endet am Leerzeichen

`git status` setzt einen Pfad mit Leerzeichen in Anführungszeichen, ` M "kunde-x/epub/Kunden und Akten.epub"`, und schreibt ihn ohne Anker wie jeden relativen Pfad. Die Pfadebene beurteilte das bloße Token bis zum ersten Leerzeichen, `kunde-x/epub/Kunden`, fand weder Endung noch Schrägstrich am Ende und ließ die Zeile im Klartext, neben den Zeilen ohne Anführungszeichen, deren Verzeichnisse sie ersetzt hatte. Die Zitatregel aus `db0a173` kam nie zum Zug: sie lief erst, wenn ein Pfad begonnen hatte, und über den Beginn eines bloßen Tokens entschied allein seine Form.

Gefunden über den Fehlerbericht vom 2. Oktober: in einem Git-Status standen ersetzte und unersetzte Zeilen zu demselben Verzeichnis nebeneinander, und das eine Vorkommen im Klartext löste die Pseudonyme daneben auf.

Reproduktion: `TestPaths_QuotedBarePathWithASpace` in `detect` hält die Formen fest, den Dateinamen aus drei Wörtern, das Verzeichnis mit Leerzeichen hinter dem ersten Segment, die drei Anführungszeichen, das Werkzeugargument in JSON, die Commit-Nachricht und die Grenzen; `TestPath_QuotedBarePathInGitStatus` im Paket `basics` schickt den Status durch Hin- und Rückweg und lässt das Modell die Datei zitiert und maskiert nennen.

Gewicht: ein Leck, das zugleich die Zuordnung verrät. Jede Datei mit Leerzeichen im Namen oder in einem Verzeichnis darüber stand im Status im Klartext, und weil `git status` die übrigen Pfade desselben Baums ohne Anführungszeichen schreibt, standen Original und Pseudonym desselben Verzeichnisses in einer Ausgabe.

Kur: steht ein Anführungszeichen unmittelbar vor dem Token und trägt der Lauf bis zum ersten Leerzeichen einen Schrägstrich, wird die Form über den Text bis zum schließenden Anführungszeichen beurteilt, wie `quotedEnd` ihn abgrenzt; Endung oder Schrägstrich am Ende zählen dann, obwohl ein Leerzeichen davor steht. Das erste Segment muss ohne Leerzeichen sein, damit `"fix kunde-x/x.go"` eine Commit-Nachricht bleibt, deren erstes Wort ein Wort ist, und ein Doppelpunkt beendet den beurteilten Text, damit `"detect/paths: fix paths.go"` eine bleibt. Ein zitierter bloßer Verzeichnispfad ohne Datei und ohne Schrägstrich am Ende bleibt außerhalb des Netzes wie der unzitierte.

Verworfen: jeden zitierten Text mit Schrägstrich als Pfad zu lesen, weil dann jede Commit-Nachricht und jede zitierte Fehlermeldung mit einem Schrägstrich-Wort ihre Wörter als Verzeichnisse gehasht bekäme. Als Preis bleibt der zitierte Satz, der mit einem Schrägstrich-Wort beginnt und ohne Doppelpunkt in einem Dateinamen endet, `"kunde/sub siehe x.go"`; sein erstes Wort geht als Verzeichnispseudonym hinaus und kommt zurück, wie es war.

Behoben mit `3228fd5` und `6a95bee`.

---

# Das Vorzeichen einer Diff-Zeile klebt am Pfad

`git diff` schreibt eine hinzugefügte oder entfernte Zeile mit ihrem Vorzeichen direkt vor dem Inhalt, `+/home/alice/kunde-x/x.go`, `-kunde-x/build/`. Plus und Minus sind Segmentzeichen, wegen `lost+found`, `c++` und der plattgedrückten Verzeichnisnamen, und so klebte das Vorzeichen am Pfad. Mit Anker war der Pfad gar keiner, weil sein Schrägstrich hinter einem Segmentzeichen stand, und die Zeile ging im Klartext hinaus, während die Kontextzeile mit führendem Leerzeichen darunter ersetzt wurde. Ohne Anker war `+kunde-x/build/` ein bloßer Pfad mit `+kunde-x` als erstem Segment: es bekam ein eigenes Pseudonym, verschieden von dem für `kunde-x`, und das Modell las eine hinzugefügte Zeile als Kontext, weil das Plus im Pseudonym verschwunden war.

Derselbe Fehlerbericht zeigte es am Diff einer `.gitignore`: zwei hinzugefügte Zeilen kamen ohne Plus und mit einem zweiten Pseudonym für dasselbe Verzeichnis beim Modell an. Den verankerten Pfad hinter dem Vorzeichen fand erst der Test.

Reproduktion: `TestPaths_DiffMarkerIsABoundary` in `detect` hält die Formen fest, beide Vorzeichen vor einem Pfad mit Schrägstrich, Tilde oder Punkten als Anker und vor einem bloßen, die Kontextzeile, den Diff-Kopf, die Flags und das plattgedrückte Verzeichnis mit und ohne Vorzeichen; `TestPath_DiffLinesRoundTrip` im Paket `basics` schickt einen Diff mit Kopf und Hunk durch Hin- und Rückweg und prüft, dass jede Zeile ihr Vorzeichen behält.

Gewicht: ein Leck und eine Verfälschung. Jede Diff-Zeile mit einem verankerten Pfad ging im Klartext hinaus, und jede mit einem bloßen kam ohne Vorzeichen an. Schreibt das Modell das Pseudonym von `+kunde-x` in eine Datei, stellt der Rückweg daraus `+kunde-x` her, mit dem Plus im Verzeichnisnamen.

Kur: ein Plus oder Minus am Zeilenanfang mit einem Pfad direkt dahinter ist eine Grenze. `diffMarker` erkennt es, `pathStart` liest das Zeichen davor als Zeilenumbruch und beginnt kein Token am Vorzeichen; der Pfad beginnt dahinter, und das Vorzeichen bleibt, wo es war. Eine Flag, die Kopfzeilen `---` und `+++` und ein plattgedrücktes Arbeitsverzeichnis, das mit einem eigenen Bindestrich beginnt, sind, was sie waren; vor einem plattgedrückten Namen ist ein Vorzeichen ein Vorzeichen.

Verworfen: Plus und Minus aus den Segmentzeichen zu nehmen, weil `lost+found`, `c++` und die plattgedrückten Namen sie brauchen; und das Vorzeichen überall vor einem Pfad als Grenze zu lesen, nicht nur am Zeilenanfang, weil `+kunde-x/x.go` mitten in der Zeile, im Wort-Diff oder in Prosa, auch ein Token sein kann. Als Grenze bleibt der Diff-Kopf, `--- a/kunde-x/x.go`, dessen Einbuchstabenpräfix im README steht.

Behoben mit `e39435c`.

---

# Ein versteckter Name beendet keinen bloßen Pfad

Der Hunk-Kopf eines Diffs nennt die Datei, zu der der Hunk gehört, `@@ -24,3 +24,9 @@ kunde-x/docs/.gitignore`, und ein Verzeichnis mit einer Punktdatei am Ende, `kunde-x/.kunderc`, schreibt `git status` genauso. Die Form eines bloßen Pfades verlangte am Ende eine Endung oder einen Schrägstrich, und ein versteckter Name ohne zweiten Punkt hat beides nicht: `.gitignore` ist für `hasFileExt` keine Endung, weil der Punkt vorn steht. Der Pfad davor blieb im Klartext, zwei Zeilen unter denselben Verzeichnissen als Pseudonym.

Im selben Bericht stand der Hunk-Kopf eines Diffs im Klartext, dessen erstes Verzeichnis sonst überall ersetzt war.

Reproduktion: `TestPaths_HiddenNameEndsABarePath` in `detect` hält den Hunk-Kopf, die Punktdatei hinter einem und hinter zwei Verzeichnissen, das Vorzeichen davor und die Gegenbeispiele fest, die Zahl hinter dem Punkt und das Satzende hinter dem Schrägstrich-Wort.

Gewicht: ein Leck, bei jedem Diff eines Repositorys mit einer Punktdatei, denn der Hunk-Kopf nennt den Pfad in jedem Hunk, und bei jeder Auflistung einer Punktdatei in bloßer Form.

Kur: ein versteckter Name am Ende, ein Punkt, ein Buchstabe und kein zweiter Punkt, ist eine fünfte Form des bloßen Pfades. Dazu stehen die üblichen versteckten Dateien eines Repositorys und eines Heimverzeichnisses auf der Bewahrliste, damit das Modell sieht, welche Datei es vor sich hat; bis dahin machte die Ebene aus einer solchen Datei am Ende eines verankerten Pfades ein Verzeichnispseudonym, weil ein Name ohne Endung als Verzeichnis gilt. Ein unbekannter versteckter Name bleibt ein Verzeichnis.

Verworfen: nichts. Als Grenze bleibt das versteckte Verzeichnis mit Punkt im Namen am Anfang, `.hidden.dir/x`, das im README steht.

Behoben mit `9d14e5a`.

---

# Beobachtungen ohne Fehlerstatus

`Walk` verwarf alles, was nach der schließenden Klammer stand, sobald eine Ersetzung stattfand: aus `{"a":"zeus.lan"}trailing` wurde `{"a":"h-0123456789ab"}`, und aus zwei aufeinanderfolgenden Objekten blieb das erste. Der Produktionsweg war davon nicht betroffen, weil `ReplaceStrings` denselben Body mit `body is not a JSON object` ablehnt und auf dem Hinweg `on_error: block` gilt. Seit `4947e0d` teilen sich beide Funktionen den Scanner, und `Walk` lehnt solche Bytes genauso ab; `TestWalk_TrailingBytesAfterObject` hält das fest.

Eine Ersetzung sortierte die Schlüssel des Objekts alphabetisch um und schrieb Escapes neu: aus `ü` wurde `ü`. Beides war deterministisch und semantisch folgenlos, weil JSON-Objekte ungeordnet sind und beide Schreibweisen dasselbe Zeichen meinen. Seit `4947e0d` bleibt beides, wie es kam: nur die Zeichenketten, die sich ändern, werden neu kodiert. `TestWalk_ReserializationIsDeterministic` prüft weiter, dass zwanzig Läufe dasselbe Byte für Byte liefern.

Ein Personen-Ersatzname ist ein gewöhnlicher Name. Schreibt das Modell ihn aus eigenem Antrieb, macht der Restorer daraus den echten: aus einem beiläufigen Satz über `Paula Wehrle` wurde einer über die reale Person. Das ist der Preis der Formtreue und lässt sich nur über die Namensauswahl kleinhalten. `TestPerson_PseudonymCollidesWithOrdinaryText` dokumentiert es.

Der Kommentar über `WordBoundary` in `detect/terms.go` beschrieb bis `65202b0` noch die Regel vor `8436b9e`, nach der ein Unterstrich ein Wortzeichen sei. Er sagt jetzt, was gilt, und dass die Regel auch für reguläre Ausdrücke gilt.

`Restorer()` fror die Zeilen beim ersten Aufruf ein, und ein `Lookup` danach trug still eine Zeile ein, die der Restorer nie sah. Seit `031f72b` ist der Restorer ein lebender Griff über die Tabelle des Gesprächs, und die Falle ist weg; `TestRestorer_LaterEntriesAreSeen` und `TestRestorer_HandleTakenEarly` halten das fest, `TestRestorer_FillThenRestore` die gewöhnliche Reihenfolge.

Eine vierstellige Versionsnummer, deren Teile alle unter 256 liegen, ist von einer Adresse nicht zu unterscheiden und wird ersetzt. Drei Teile bleiben unberührt, ebenso alles mit einem Teil über 255, was die meisten Firmware- und Windows-Nummern ausschließt. Kein Leck, aber das Modell liest eine Adresse, wo eine Version steht. `TestRange_VersionNumbersAreNotAddresses`.

Die Musterebene übergeht die Adressen, die in Handbüchern stehen: die drei Dokumentationsnetze, Loopback, die unbestimmte Adresse, die Rundsendeadresse, Link-Local und Multicast. Ein eingefügtes Handbuch erzeugt also kein Rauschen. `TestRange_WhatThePatternLayerReports` listet die Entscheidung Bereich für Bereich.

Der Rückweg unterscheidet nach Art des Ersatzwertes: die strukturellen Formen kommen auch in Versalien zurück, ein Personen-Ersatzname nur in seiner eigenen Schreibung. Beides ist plausibel — das Modell schreibt Rechnernamen gern groß, und ein Name in Versalien wäre ein anderes Wort —, steht aber nirgends geschrieben. `TestCC_PseudonymAsTheModelWritesIt` und `TestCC_PersonPseudonymIgnoresCase`.

Was das Modell am Ersatzwert selbst ändert, ist verloren: ein Umbruch mitten im Wort, ein eingefügtes Leerzeichen, eine Kürzung mit Auslassungspunkten. Der Ersatzwert bleibt dann beim Nutzer stehen. Das ist die Kehrseite der Formtreue und nicht zu beheben; es zu kennen hilft beim Lesen einer Antwort, in der ein einzelnes Kürzel übrig geblieben ist.

`KindURL` hat keinen eigenen Renderer und fällt auf das undurchsichtige Token zurück, das sonst Zugangsdaten bekommen. Aus einer Adresse wird damit ein Wort, mit dem das Modell nicht arbeiten kann: es kann keinen Pfad anhängen, keinen Parameter ändern, keine zweite Adresse derselben Herkunft zuordnen. Das Muster ist standardmäßig aus, die Sache also nicht dringend; wer es einschaltet, sollte wissen, was er eintauscht. Eine Adresse zerfällt sauber in Schema, Rechnername und Pfadsegmente, für die es Renderer längst gibt. `TestForm_EveryKindKeepsItsShape` hält es fest, als einziger roter Punkt unter siebzehn Arten.

Der Stream stellt vier benannte Felder wieder her, der Weg am Stück jeden Wert, den die Sperrliste nicht deckt. Beides ist so dokumentiert, aber die zwei Wege sagen damit Verschiedenes über denselben Body: die Meldung eines Fehlerereignisses, ein `content_block_start` vom Typ `tool_use` mit vorbelegtem `input` und der Inhalt eines Suchergebnisses behalten ihre Ersatzwerte. Nach dem Kapitel über den Gesprächsverlauf bleiben die dann für immer stehen. Der Denkblock bleibt in beiden Wegen richtigerweise unangetastet.

Der Stream löst die Neukodierung eines Ereignisses viel häufiger aus als der Weg am Stück: ein Delta ohne eigenen Treffer wird neu geschrieben, sobald der Nachbar etwas zurückhielt, und ein halbes Surrogat darin verschwindet dabei schon auf der Leitung. Seit `4947e0d` ist das die einzige Stelle, an der ein halbes Surrogat noch verändert wird; das Kapitel dazu sagt, warum es dabei bleibt.

Ein `content_block_stop` ohne Index leert den Rückhalt jedes offenen Blocks, weil derselbe Wert minus eins zugleich „kein Index“ und „alle Blöcke“ bedeutet. Die API schickt den Index immer mit; es ist eine Härtung, kein Betriebsfehler.

Die Vorschicht, die Mailadressen befördert, wächst quadratisch mit der Zahl der Adressen im Text, weil sie für jeden Mailtreffer alle Treffer der früheren Schichten durchläuft. Ein Mailserver-Protokoll mit dem Rechnernamen in jeder Zeile ist genau dieser Fall und im Alltag der Normalfall; bei viertausend Zeilen wird es messbar. Einmal je Scan nach Startposition sortieren und binär suchen genügt. Dieselbe Vorschicht nimmt einem Term seine Art, wenn der Term selbst eine vollständige Mailadresse ist: er kommt dann als Adresse zurück, nicht als Name. Und der Vertrag von `Composite` beschreibt die Vorschicht überhaupt nicht, was die nächste Änderung an der Rangfolge unnötig schwer macht.

Ein geschachteltes `Composite` verliert die Abschirmung: das Merkmal, das einen ausgeschlossenen Treffer kennzeichnet, überlebt die Grenze nicht. Heute schachtelt niemand; wer es tut, sollte es wissen.

---

# Was hält

Der Round-Trip überstand jede geprüfte Umgebung: Anführungszeichen, Klammern, Doppelpunkt, Schrägstrich, Gedankenstrich, Zeilenumbruch, URL, mehrfaches Vorkommen. Ein zweiter Durchlauf über bereits ersetzten Text ändert nichts, das Wiederherstellen ist idempotent, überlappende Terme lösen sich nach der längeren Übereinstimmung auf, und ein Literal mit Regex-Metazeichen wird literal behandelt. Die zerlegte Unicode-Schreibweise wird erkannt und kommt unverändert zurück, ein Text ohne Treffer bleibt Byte für Byte gleich.

Auf der JSON-Seite bleiben Zahlenschreibweisen erhalten, auch `1e400` und dreißigstellige Ganzzahlen. Fünftausend Verschachtelungsebenen laufen ohne Absturz durch. Der SSE-Parser nimmt CRLF, fehlendes Leerzeichen nach `data:`, führende Kommentarzeilen und Ereignisse ohne `event:`-Zeile. Die doppelte Kodierung in `partial_json` übersteht Anführungszeichen, Backslash, Tabulator und Emoji unbeschadet, und ein Ersatzwert mit JSON-Metazeichen zerstört den Body nicht. Bodies mit führendem oder abschließendem Leerraum werden angenommen und der Leerraum erhalten.

Auf der Betriebsseite kam derselbe Rechnername unverändert zurück, gleich ob er hinter `ssh`, in einer `scp`-Quelle mit Doppelpunkt, in einer URL mit Port, in einem `Host`-Block, in `/etc/hosts`, hinter `ProxyJump=`, in `ssh://` für Docker, als Präfix eines Sicherungsdateinamens oder als Wert einer Umgebungsvariable stand; in keiner der dreizehn Formen blieb das Original sichtbar. Adressen behalten Port, Präfixlänge und die IPv6-Klammern, eine MAC bleibt eine MAC. Die acht geprüften Konfigurationsformen — YAML mit und ohne Anführungszeichen, INI, Listenpunkt, `DATABASE_URL`, systemd-`ExecStart`, `/etc/hosts` mit Kommentar und ein JSON-Feld — laufen sauber hin und zurück. Spaltenbündige Ausgaben verrutschen, weil der Ersatzwert länger ist als der Rechnername; der Text bleibt richtig, nur die Tabelle sieht schief aus.

Nebenläufigkeit und Maßstab geben keinen Anlass zur Sorge. Der Race-Detektor bleibt still, während zweiunddreißig Goroutinen in dieselbe Tabelle schreiben und zweiunddreißig weitere daraus wiederherstellen, und ebenso beim Ablegen, Holen, Löschen und Kehren im Speicher aus sechzehn Richtungen. Ein Protokoll aus zwanzigtausend Zeilen und 1,6 Megabyte läuft in 150 Millisekunden durch den Hinweg und in 44 durch den Rückweg; die Tabelle hat danach zwanzigtausend Einträge, und ein Stück der Antwort dagegen zu prüfen kostet weniger als eine Mikrosekunde. Ein Bildschirmfoto von 1,8 Megabyte als base64 im Body ist in acht Millisekunden abgearbeitet, mit und ohne Treffer. Die Grenzen des Verfahrens liegen also nicht bei der Rechenzeit. Ein Ersatzwert je Wert bleibt allerdings für immer in der Tabelle, auch der aus einem einmal eingefügten Protokoll; bei zwanzigtausend Einträgen fällt das nicht auf, eine Obergrenze gibt es aber nicht.

Der Fragment-Round-Trip hält, worauf ein Editierwerkzeug angewiesen ist: eine einzelne Zeile, eine Zeile ohne Zeilenumbruch, der nackte Ersatzwert, derselbe mit Doppelpunkt und Port, in Anführungszeichen und über zwei Zeilen kommen alle byte-genau zurück, und ein Patch mit Hunk-Kopf, Kontextzeilen und leerer Kontextzeile passt hinterher noch. Compilermeldungen und Stapelabzüge behalten Zeile und Spalte, gleich ob der Pfad absolut, relativ, eingerückt oder in Anführungszeichen steht.

Der Denkblock bleibt unangetastet, in jeder geprüften Position: oben im Baum, zweifach verschachtelt, in der geschwärzten Fassung und neben einem Geschwisterelement, das im selben Durchgang richtig gefiltert wird. Werkzeugname, `metadata.user_id` und Modellname bleiben ebenfalls stehen, während Nutzertext, Systemtext, Werkzeugbeschreibung, `tool_use.input` und Werkzeugergebnis ersetzt werden.

Die Pfadebene bringt jede erkannte Form unverändert zurück, doppelte Schrägstriche, `..`, Tilde, Leerzeichen im Dateinamen, das kodierte Leerzeichen eines Markdown-Links in beiden Schreibweisen und Umlaute eingeschlossen, und ihre Bewahrliste kennt fünfundzwanzig der dreißig Verzeichnisnamen, die in jedem Projekt vorkommen; ersetzt werden nur die projekteigenen. Dateinamen bleiben lesbar, ein Term innerhalb eines Dateinamens wird trotzdem gefunden.

Der Namensraum hält dem Druck stand: zweiundsiebzig Namen im Vorrat, hundertvierundvierzig Personen im Text, hundertvierundvierzig verschiedene Ersatznamen und keine Kollision; jeder löst sich auf die Person auf, für die er gemacht wurde, und ein Name, den der Nutzer selbst schützen lässt, wird nicht mehr ausgegeben. Der Salt bleibt über das wachsende Gespräch derselbe, mit Kopfzeile wie ohne, und zwei Gespräche teilen ihn nicht. Der Rückhalt schneidet nie mitten durch ein Zeichen, auch nicht bei Emoji oder chinesischer Schrift.

Die Formtreue trägt durch alle siebzehn Arten bis auf die Adresse. Eine Ersatz-IBAN hat dasselbe Länderkürzel, dieselbe Länge und eine gültige Prüfsumme nach mod 97; eine UUID behält die Gruppierung 8-4-4-4-12, ein Fingerabdruck seine dreiundvierzig Zeichen hinter `SHA256:`, eine MAC ihre sechs Paare, ein Dateiname seine Endung und eine Netzmaske ihre Präfixlänge. Derselbe Wert unter zwei Arten bekommt zwei Ersatzwerte, und beide lösen sich richtig auf.

Der Stream trägt seine gewöhnliche Arbeit ohne Verlust. Ein Block, der in Fragmenten von drei Byte ankommt, ergibt beim Client denselben Text wie am Stück restauriert, und die Reihenfolge der Ereignisse bleibt erhalten. Ein Block aus lauter Ein-Zeichen-Deltas kommt vollständig an, obwohl unterwegs 41 von 70 Fragmenten in den Rückhalt fallen. Zwei gleichzeitig offene Blöcke halten getrennte Rückhalte, jedes Stop-Ereignis leert nur seinen eigenen, und ein Ersatzwert auf der Naht zwischen zwei Blöcken wird in seine eigene Hälfte ausgespült. Keep-alives ändern nichts, gleich ob sie eigenständig kommen oder an einem Delta kleben, gestörte Reihenfolgen verlieren nichts, und die Fragmente eines Werkzeugaufrufs ergeben bei jeder Schnittbreite von einem bis sieben Byte wieder gültiges JSON, auch wenn der Originalwert ein Anführungszeichen trägt.

Die Eigenschaften halten auch über zufällige Eingaben. Zehn Fuzz-Ziele prüfen den Round-Trip über Terme, Muster, Ausdrücke und das Composite, die Grenzen des Rückhalts, die Form der Ersatzwerte und die Trennung der Werte in der Tabelle; die Läufe fanden genau die Fälle, die oben als Befunde stehen, und darüber hinaus nichts. Das ist der eigentliche Wert dieses Bereichs: die bekannten Grenzfälle sind vollständig, nicht nur zahlreich.

---

# Was diese Tests nicht erreichen

Solange die Tests ein eigenes Modul neben dem Klon waren, erreichten sie nur `detect`, `pseudo`, `mapping` und `payload`; der Interceptor, `stream.go`, der Lader der Term-Datei, die Prüfung der Konfiguration und das Prüfprotokoll blieben außen vor, weil sie in `package main` liegen. Diese Schranke ist mit dem Umzug ins Modul gefallen. Der Nachbau des Streamablaufs ist weg, und die Proben laufen gegen `streamState` selbst; siebzehn von neunzehn halten dabei genau so wie gegen den Nachbau, womit auch die Befunde des Stream-Kapitels nicht mehr an dessen Treue hängen. Ungeprüft bleibt die Nebenläufigkeit eines Streamzustands unter den Aufrufen des Hosts und die Frage, ob der Host einen fehlerhaften Chunk wirklich unverändert weiterreicht und einen unterdrückten wirklich unterdrückt.

Ebenso offen ist der Weg durch den echten HTTP-Pfad: ob `on_error: block` bei einem fehlerhaften Body wirklich blockt, ob die Grenze von zweiunddreißig Megabyte sauber greift, was ein mitten im Stream abgebrochener Anbieter mit dem zurückgehaltenen Rest macht, und ob das Prüfprotokoll schreibt, was es schreiben soll. Dass ein `content_block_start` mit gefülltem `input` oder ein Suchergebnis über den Stream kommt, ist der Schnittstellenbeschreibung entnommen und nicht an einem Mitschnitt belegt; für den Wortlaut einer Fehlermeldung gilt dasselbe.

Ebenfalls offen: betterleaks hinter seinem Build-Tag, die Erkennung von Zugangsdaten also, und alles, was nicht dem Anthropic-Schema folgt. Die Race beim Neuladen der Konfiguration im laufenden Host, der Punkt aus dem Übergabedokument, ist hier nicht zu prüfen; was geprüft ist, ist die Nebenläufigkeit der Bausteine, und die hält.
