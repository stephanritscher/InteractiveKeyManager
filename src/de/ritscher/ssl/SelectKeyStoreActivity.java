/* MemorizingTrustManager - a TrustManager which asks the user about invalid
 *  certificates and memorizes their decision.
 *
 * Copyright (c) 2010 Georg Lukas <georg@op-co.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package de.ritscher.ssl;


import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.DialogInterface.OnCancelListener;
import android.content.DialogInterface.OnClickListener;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.text.InputType;
import android.util.Log;
import android.widget.EditText;

public class SelectKeyStoreActivity extends Activity
        implements OnClickListener, OnCancelListener, KeyChainAliasCallback, ActivityCompat
        .OnRequestPermissionsResultCallback  {

    private final static String TAG = "SelectKeyStoreActivity";
    private final static int KEYSTORE_INTENT = 1380421;
    private final static int PERMISSIONS_REQUEST_EXTERNAL_STORAGE_BEFORE_FILE_CHOOSER = 1001;

    int decisionId;

    int state = IKMDecision.DECISION_INVALID;
    String param = null;

    AlertDialog decisionDialog, hostnameDialog;
    EditText hostnameInput;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        Log.d(TAG, "onCreate");
        super.onCreate(savedInstanceState);
        hostnameInput = new EditText(this);
        hostnameInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        decisionDialog = new AlertDialog.Builder(this).setTitle(R.string.ikm_select_cert)
                .setPositiveButton(R.string.ikm_decision_file, this)
                .setNeutralButton(R.string.ikm_decision_keychain, this)
                .setNegativeButton(R.string.ikm_decision_abort, this)
                .setOnCancelListener(this)
                .create();
        hostnameDialog = new AlertDialog.Builder(this).setTitle(R.string.ikm_select_host)
                .setView(hostnameInput)
                .setPositiveButton(R.string.ikm_decision_host, this)
                .setNeutralButton(R.string.ikm_decision_all, this)
                .setNegativeButton(R.string.ikm_decision_abort, this)
                .setOnCancelListener(this)
                .create();
    }

    @Override
    public void onResume() {
        super.onResume();
        Intent i = getIntent();
        decisionId = i.getIntExtra(InteractiveKeyManager.DECISION_INTENT_ID, IKMDecision
                .DECISION_INVALID);
        String cert = i.getStringExtra(InteractiveKeyManager.DECISION_INTENT_CERT);
        String hostname = i.getStringExtra(InteractiveKeyManager.DECISION_INTENT_HOSTNAME);
        int port = i.getIntExtra(InteractiveKeyManager.DECISION_INTENT_PORT, 0);
        Log.d(TAG, "onResume with " + i.getExtras() + " decId=" + decisionId + " data=" + i
                .getData());
        decisionDialog.setMessage(cert);

        hostnameInput.setText(hostname + ":" + port);
        if (state == IKMDecision.DECISION_INVALID) {
            decisionDialog.show();
        } else {
            hostnameDialog.show();
        }
    }

    @Override
    protected void onPause() {
        if (decisionDialog.isShowing()) {
            decisionDialog.dismiss();
        }
        if (hostnameDialog.isShowing()) {
            hostnameDialog.dismiss();
        }
        super.onPause();
    }

    void sendDecision(int state, String param, String hostname, Integer port) {
        Log.d(TAG, "sendDecision(" + state + ", " + param + ", " + hostname + ", " + port + ")");
        decisionDialog.dismiss();
        hostnameDialog.dismiss();
        InteractiveKeyManager.interactResult(decisionId, state, param, hostname, port);
        finish();
    }

    public void onClick(DialogInterface dialog, int btnId) {
        if (dialog == decisionDialog) {
            switch (btnId) {
                case DialogInterface.BUTTON_POSITIVE:
                    if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) !=
                            PackageManager.PERMISSION_GRANTED) {
                        Log.d(TAG, "Requesting permission READ_EXTERNAL_STORAGE");
                        ActivityCompat.requestPermissions(this,
                                new String[]{Manifest.permission.READ_EXTERNAL_STORAGE},
                                PERMISSIONS_REQUEST_EXTERNAL_STORAGE_BEFORE_FILE_CHOOSER);
                    } else {
                        Log.d(TAG, "Verified permission READ_EXTERNAL_STORAGE");
                        /* Permission callback invokes file chooser */
                        onRequestPermissionsResult (PERMISSIONS_REQUEST_EXTERNAL_STORAGE_BEFORE_FILE_CHOOSER,
                                new String[]{Manifest.permission.READ_EXTERNAL_STORAGE},
                                new int[]{PackageManager.PERMISSION_GRANTED});
                    }
                    break;
                case DialogInterface.BUTTON_NEUTRAL:
                    KeyChain.choosePrivateKeyAlias(this, this, null, null, null, -1, null);
                    break;
                default:
                    sendDecision(IKMDecision.DECISION_ABORT, null, null, null);
            }
        } else if (dialog == hostnameDialog) {
            switch (btnId) {
                case DialogInterface.BUTTON_POSITIVE:
                    String hostname[] = hostnameInput.getText().toString().split(":");
                    Integer port = null;
                    if (hostname.length >= 2) {
                        port = Integer.valueOf(hostname[1]);
                    }
                    sendDecision(state, param, hostname[0], port);
                    break;
                case DialogInterface.BUTTON_NEUTRAL:
                    sendDecision(state, param, null, null);
                    break;
                default:
                    sendDecision(IKMDecision.DECISION_ABORT, null, null, null);
            }
        }
    }

    public void onCancel(DialogInterface dialog) {
        sendDecision(IKMDecision.DECISION_ABORT, null, null, null);
    }

    public void onRequestPermissionsResult (int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == PERMISSIONS_REQUEST_EXTERNAL_STORAGE_BEFORE_FILE_CHOOSER) {
            if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.d(TAG, "Permission READ_EXTERNAL_STORAGE was granted.");
                /* Start file chooser */
                Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
                intent.setType("file/*");
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                startActivityForResult(Intent.createChooser(intent, this.getString(R.string
                        .ikm_select_keystore)), KEYSTORE_INTENT);
            } else {
                Log.d(TAG, "Permission READ_EXTERNAL_STORAGE was denied.");
                sendDecision(IKMDecision.DECISION_ABORT, null, null, null);
            }
        }
    }

    @Override
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == KEYSTORE_INTENT && resultCode == Activity.RESULT_OK) {
            state = IKMDecision.DECISION_FILE;
            param = data.getData().getPath();
            decisionDialog.dismiss();
            hostnameDialog.show();
        }
    }

    @Override
    public void alias(final String alias) {
        Log.d(TAG, "alias(" + alias + ")");
        if (alias != null) {
            state = IKMDecision.DECISION_KEYCHAIN;
            param = alias;
            decisionDialog.dismiss();
            hostnameDialog.show();
        } else {
            sendDecision(IKMDecision.DECISION_ABORT, null, null, null);
        }
    }
}
