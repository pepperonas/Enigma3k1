# Enigma3k1

Eine moderne, benutzerfreundliche Verschlüsselungs-App für Android mit Material Design.

## Beschreibung

Enigma3k1 ist eine umfassende Verschlüsselungs-App, die verschiedene kryptografische Algorithmen in
einer intuitiven Benutzeroberfläche vereint. Sie bietet sichere Verschlüsselungsmethoden für Texte
und Dateien, inklusive Schlüsselverwaltung.

## Features

- **AES-Verschlüsselung:** Symmetrische Verschlüsselung mit AES-GCM und verschiedenen
  Schlüsselgrößen (128, 192, 256 Bit)
- **RSA-Verschlüsselung:** Asymmetrische Verschlüsselung mit Schlüsselpaaren (1024, 2048, 4096 Bit)
- **Caesar-Verschlüsselung:** Klassische Verschiebechiffre mit Brute-Force-Option
- **Dateiverschlüsselung:** Verschlüsseln und Entschlüsseln von Dateien mit AES
- **Schlüsselverwaltung:** Generieren, Speichern und Verwalten von kryptografischen Schlüsseln
- **Material Design:** Moderne und intuitive Benutzeroberfläche im dunklen Design
- **Schlüsselexport/-import:** Teilen von (öffentlichen) Schlüsseln mit anderen Nutzern
- **Passwortschutz:** Option zum Schutz privater Schlüssel mit Passwörtern

## Screenshots

*Screenshots werden hinzugefügt*

## Anforderich ungen

- Android 5.0 (API Level 21) oder höher
- Berechtigungen für Dateizugriff bei Verwendung der Dateiverschlüsselung

## Installation

1. APK herunterladen von [Releases](https://github.com/pepperonas/enigma3k1/releases)
2. Installation auf dem Android-Gerät erlauben (eventuell muss "Installation aus unbekannten
   Quellen" aktiviert werden)
3. App starten

## Verwendung

### AES-Verschlüsselung

1. Gib den zu verschlüsselnden Text ein
2. Wähle eine Schlüsselgröße (standardmäßig 256 Bit)
3. Gib ein Passwort ein oder generiere einen zufälligen Schlüssel
4. Drücke "Verschlüsseln" und kopiere das Ergebnis
5. Du kannst Schlüssel für spätere Verwendung speichern

### RSA-Verschlüsselung

1. Generiere ein RSA-Schlüsselpaar oder importiere einen öffentlichen Schlüssel
2. Gib den zu verschlüsselnden Text ein
3. Wähle zwischen eigenem Schlüssel oder externem öffentlichen Schlüssel
4. Verschlüsselung ist nur mit einem öffentlichen Schlüssel möglich
5. Entschlüsselung erfordert den entsprechenden privaten Schlüssel

### Dateiverschlüsselung

1. Wähle die zu verschlüsselnden Dateien aus
2. Gib ein Passwort ein oder generiere einen Schlüssel
3. Verschlüsselte Dateien erhalten die Endung ".enc"
4. Verschlüsselte Dateien können innerhalb der App geöffnet oder geteilt werden

## GitHub Actions Workflows

### Release-Build erstellen

Um eine neue Release-Version der App zu erstellen:

1. Gehe zu "Actions" > "Build Release APK" auf GitHub
2. Klicke auf "Run workflow"
3. Gib die neue Versionsnummer (z.B. "1.0.0") und den Versionscode (z.B. "2") ein
4. Klicke auf "Run workflow"

Der Workflow wird automatisch:
- Eine Release-APK mit der angegebenen Versionsnummer erstellen
- Die gebaute APK-Datei im Build-Log anzeigen

**Nach dem Build:**
1. Baue die APK auch lokal mit `./gradlew assembleRelease`
2. Aktualisiere die Versionsnummer in `app/build.gradle` manuell und committe die Änderung
3. Wenn gewünscht, kannst du ein manuelles GitHub Release erstellen und die APK hochladen

### Debug-Build erstellen

Für einen schnellen Debug-Build ohne Versionsaktualisierung:

1. Gehe zu "Actions" > "Build Debug APK" auf GitHub
2. Klicke auf "Run workflow"

Die Debug-APK wird als Artefakt im Workflow bereitgestellt.

## Technische Details

Die App nutzt folgende kryptografische Verfahren:

- **AES:** Advanced Encryption Standard im GCM-Modus (Galois/Counter Mode) mit IV
- **RSA:** RSA/ECB/PKCS1Padding mit variabler Schlüsselgröße
- **Schlüsselableitung:** PBKDF2 für passwortbasierte Schlüssel

Verwendete Bibliotheken:

- AndroidX-Komponenten
- Google Material Design Components
- GSON für JSON-Serialisierung

## Entwicklung

Die App wurde mit Android Studio entwickelt und verwendet Java als Programmiersprache.

### Build

```bash
./gradlew assembleDebug
```

### Installation

```bash
./gradlew installDebug
```

## Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).

## Entwickler

**Martin Pfeffer**

- GitHub: [https://github.com/pepperonas](https://github.com/pepperonas)

---

**Hinweis:** Diese App dient Bildungszwecken und der persönlichen Nutzung. Für hochsensible Daten
oder professionelle Anwendungen sollten spezialisierte Sicherheitslösungen verwendet werden.