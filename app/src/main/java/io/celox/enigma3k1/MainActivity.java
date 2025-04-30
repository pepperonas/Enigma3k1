package io.celox.enigma3k1;

import android.os.Bundle;
import android.view.MenuItem;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.appcompat.app.ActionBarDrawerToggle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.GravityCompat;
import androidx.drawerlayout.widget.DrawerLayout;
import androidx.fragment.app.Fragment;

import com.google.android.material.navigation.NavigationView;

import io.celox.enigma3k1.fragments.AesFragment;
import io.celox.enigma3k1.fragments.CaesarFragment;
import io.celox.enigma3k1.fragments.FileFragment;
import io.celox.enigma3k1.fragments.RsaFragment;

public class MainActivity extends AppCompatActivity implements NavigationView.OnNavigationItemSelectedListener {

    private DrawerLayout drawerLayout;
    private NavigationView navigationView;
    private TextView toolbarTitle;
    private Toolbar toolbar;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        setupUI();

        // Standardfragment beim Start
        if (savedInstanceState == null) {
            loadFragment(new AesFragment(), "AES Verschlüsselung");
            navigationView.setCheckedItem(R.id.nav_aes);
        }
    }

    private void setupUI() {
        // Toolbar einrichten
        toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        getSupportActionBar().setDisplayShowTitleEnabled(false);
        toolbarTitle = findViewById(R.id.toolbar_title);

        // Navigation Drawer einrichten
        drawerLayout = findViewById(R.id.drawer_layout);
        navigationView = findViewById(R.id.nav_view);
        navigationView.setNavigationItemSelectedListener(this);

        ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(
                this, drawerLayout, toolbar,
                R.string.navigation_drawer_open, R.string.navigation_drawer_close
        );
        drawerLayout.addDrawerListener(toggle);
        toggle.syncState();
    }

    private void loadFragment(Fragment fragment, String title) {
        // Fragment laden
        getSupportFragmentManager().beginTransaction()
                .replace(R.id.fragment_container, fragment)
                .commit();

        // Titel aktualisieren
        toolbarTitle.setText(title);

        // Drawer schließen
        drawerLayout.closeDrawer(GravityCompat.START);
    }

    @Override
    public boolean onNavigationItemSelected(@NonNull MenuItem item) {
        int id = item.getItemId();

        if (id == R.id.nav_aes) {
            loadFragment(new AesFragment(), "AES Verschlüsselung");
        } else if (id == R.id.nav_rsa) {
            loadFragment(new RsaFragment(), "RSA Verschlüsselung");
        } else if (id == R.id.nav_caesar) {
            loadFragment(new CaesarFragment(), "Caesar Verschlüsselung");
        } else if (id == R.id.nav_files) {
            loadFragment(new FileFragment(), "Dateiverschlüsselung");
        } else if (id == R.id.nav_export) {
            // Schlüsselexport Dialogfenster anzeigen
            // TODO: Implementieren
        } else if (id == R.id.nav_import) {
            // Schlüsselimport starten
            // TODO: Implementieren
        }

        return true;
    }

    @Override
    public void onBackPressed() {
        // Drawer zuerst schließen, wenn geöffnet
        if (drawerLayout.isDrawerOpen(GravityCompat.START)) {
            drawerLayout.closeDrawer(GravityCompat.START);
        } else {
            super.onBackPressed();
        }
    }
}