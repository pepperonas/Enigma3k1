#!/bin/bash
# Dieses Skript erstellt die Projektstruktur für Enigma3k1 Android

# Standard-Android-Projektstruktur mit angepasstem Paketpfad
mkdir -p app/src/main/java/io/celox/enigma3k1
mkdir -p app/src/main/java/io/celox/enigma3k1/fragments
mkdir -p app/src/main/java/io/celox/enigma3k1/crypto
mkdir -p app/src/main/java/io/celox/enigma3k1/models
mkdir -p app/src/main/java/io/celox/enigma3k1/utils
mkdir -p app/src/main/java/io/celox/enigma3k1/adapters
mkdir -p app/src/main/res/layout
mkdir -p app/src/main/res/menu
mkdir -p app/src/main/res/values
mkdir -p app/src/main/res/drawable
mkdir -p app/src/main/res/mipmap-hdpi
mkdir -p app/src/main/res/mipmap-mdpi
mkdir -p app/src/main/res/mipmap-xhdpi
mkdir -p app/src/main/res/mipmap-xxhdpi
mkdir -p app/src/main/res/mipmap-xxxhdpi

# Gradle-Struktur
mkdir -p app
mkdir -p gradle/wrapper

# Hauptaktivität und Fragments
touch app/src/main/java/io/celox/enigma3k1/MainActivity.java
touch app/src/main/java/io/celox/enigma3k1/fragments/AesFragment.java
touch app/src/main/java/io/celox/enigma3k1/fragments/RsaFragment.java
touch app/src/main/java/io/celox/enigma3k1/fragments/CaesarFragment.java
touch app/src/main/java/io/celox/enigma3k1/fragments/FileFragment.java

# Crypto-Utilities
touch app/src/main/java/io/celox/enigma3k1/crypto/AesUtils.java
touch app/src/main/java/io/celox/enigma3k1/crypto/RsaUtils.java
touch app/src/main/java/io/celox/enigma3k1/crypto/CaesarUtils.java
touch app/src/main/java/io/celox/enigma3k1/crypto/FileUtils.java

# Modelle
touch app/src/main/java/io/celox/enigma3k1/models/AesKey.java
touch app/src/main/java/io/celox/enigma3k1/models/RsaKeyPair.java
touch app/src/main/java/io/celox/enigma3k1/models/EncryptedFile.java

# Utils
touch app/src/main/java/io/celox/enigma3k1/utils/KeyStorageUtils.java
touch app/src/main/java/io/celox/enigma3k1/utils/UiUtils.java

# Adapter
touch app/src/main/java/io/celox/enigma3k1/adapters/AesKeyAdapter.java
touch app/src/main/java/io/celox/enigma3k1/adapters/RsaKeyAdapter.java
touch app/src/main/java/io/celox/enigma3k1/adapters/FileAdapter.java

# Layouts
touch app/src/main/res/layout/activity_main.xml
touch app/src/main/res/layout/fragment_aes.xml
touch app/src/main/res/layout/fragment_rsa.xml
touch app/src/main/res/layout/fragment_caesar.xml
touch app/src/main/res/layout/fragment_file.xml
touch app/src/main/res/layout/item_key.xml
touch app/src/main/res/layout/item_file.xml
touch app/src/main/res/layout/nav_header.xml
touch app/src/main/res/layout/dialog_password.xml

# Menüs
touch app/src/main/res/menu/drawer_menu.xml
touch app/src/main/res/menu/main_menu.xml

# Drawable-Ressourcen
touch app/src/main/res/drawable/ic_shield.xml
touch app/src/main/res/drawable/ic_key.xml
touch app/src/main/res/drawable/ic_lock.xml
touch app/src/main/res/drawable/ic_file.xml
touch app/src/main/res/drawable/ic_save.xml
touch app/src/main/res/drawable/ic_upload.xml
touch app/src/main/res/drawable/ic_content_copy.xml
touch app/src/main/res/drawable/ic_refresh.xml
touch app/src/main/res/drawable/bg_error_message.xml
touch app/src/main/res/drawable/bg_info_message.xml
touch app/src/main/res/drawable/bg_card.xml

# Werte-Ressourcen
touch app/src/main/res/values/colors.xml
touch app/src/main/res/values/styles.xml
touch app/src/main/res/values/strings.xml
touch app/src/main/res/values/arrays.xml
touch app/src/main/res/values/dimens.xml

# Manifest und Gradle-Dateien
touch app/src/main/AndroidManifest.xml
touch app/build.gradle
touch build.gradle
touch gradle.properties
touch settings.gradle
touch local.properties
touch gradlew
touch gradlew.bat
touch gradle/wrapper/gradle-wrapper.properties
touch gradle/wrapper/gradle-wrapper.jar

# Sonstige Projektdateien
touch README.md
touch .gitignore

# Mache Shell-Skripte ausführbar
chmod +x gradlew

# Minimaler Inhalt für die MainActivity mit korrektem Paket-Namen
cat > app/src/main/java/io/celox/enigma3k1/MainActivity.java << 'EOF'
package io.celox.enigma3k1;

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        // Hier beginnt Deine Implementierung
    }
}
EOF

# AndroidManifest mit korrektem Paket-Namen
cat > app/src/main/AndroidManifest.xml << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="io.celox.enigma3k1">

    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">
        
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
        
    </application>

</manifest>
EOF

# Build.gradle Datei mit richtigem Paket-Namen
cat > app/build.gradle << 'EOF'
plugins {
    id 'com.android.application'
}

android {
    compileSdk 34

    defaultConfig {
        applicationId "io.celox.enigma3k1"
        minSdk 21
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }

    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
}

dependencies {
    implementation 'androidx.appcompat:appcompat:1.6.1'
    implementation 'com.google.android.material:material:1.10.0'
    implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
}
EOF

# Settings.gradle mit Projektname
cat > settings.gradle << 'EOF'
rootProject.name = 'Enigma3k1'
include ':app'
EOF

echo "Enigma3k1 Android-Projektstruktur wurde erstellt."
echo "Alle Dateien wurden angelegt."
echo "Das Projekt befindet sich im Verzeichnis: Enigma3k1"
