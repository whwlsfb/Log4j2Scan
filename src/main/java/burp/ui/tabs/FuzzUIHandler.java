package burp.ui.tabs;

import burp.BurpExtender;
import burp.utils.Config;
import burp.utils.UIUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.util.ArrayList;

public class FuzzUIHandler {
    private BurpExtender parent;
    private JPanel mainPanel;

    private JTabbedPane settingsPanel;

    private JComboBox fuzzModeSelector;
    private JCheckBox enabled_fuzz_header;
    private JCheckBox enabled_fuzz_url;
    private JCheckBox enabled_fuzz_body;
    private JCheckBox enabled_fuzz_cookie;
    private JCheckBox enabled_fuzz_body_form;
    private JCheckBox enabled_fuzz_body_json;
    private JCheckBox enabled_fuzz_body_xml;
    private JCheckBox enabled_fuzz_body_multipart;
    private JCheckBox enabled_fuzz_bad_json;

    public FuzzUIHandler(BurpExtender parent) {
        this.parent = parent;
    }

    public JPanel getPanel() {
        mainPanel = new JPanel();
        mainPanel.setAlignmentX(0.0f);
        mainPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
        mainPanel.setLayout(new BoxLayout(mainPanel, 1));


        settingsPanel = new JTabbedPane();
        settingsPanel.addTab("Basic", getFuzzSettingPanel());
        mainPanel.add(settingsPanel);
        loadConfig();
        return mainPanel;
    }

    public JPanel getFuzzSettingPanel() {
        JPanel panel1 = new JPanel();
        panel1.setAlignmentX(0.0f);
        panel1.setBorder(new EmptyBorder(10, 10, 10, 10));
        panel1.setLayout(new BoxLayout(panel1, 1));

        JPanel subPanel0 = UIUtil.GetXJPanel();
        fuzzModeSelector = new JComboBox(GetFuzzModes());
        fuzzModeSelector.setMaximumSize(fuzzModeSelector.getPreferredSize());
        fuzzModeSelector.setSelectedIndex(0);
        subPanel0.add(new JLabel("Fuzz Mode: "));
        subPanel0.add(fuzzModeSelector);

        JPanel subPanel1 = UIUtil.GetXJPanel();
        enabled_fuzz_header = new JCheckBox("Enable Header Fuzz");
        subPanel1.add(enabled_fuzz_header);

        JPanel subPanel2 = UIUtil.GetXJPanel();
        enabled_fuzz_url = new JCheckBox("Enable Url Fuzz");
        subPanel2.add(enabled_fuzz_url);

        JPanel subPanel3 = UIUtil.GetXJPanel();
        enabled_fuzz_cookie = new JCheckBox("Enable Cookie Fuzz");
        subPanel3.add(enabled_fuzz_cookie);

        JPanel subPanel4 = UIUtil.GetXJPanel();
        enabled_fuzz_body = new JCheckBox("Enable Body Fuzz");
        enabled_fuzz_body.addActionListener(e -> {
            if (enabled_fuzz_body.isSelected()) {
                enabled_fuzz_body_form.setEnabled(true);
                enabled_fuzz_body_json.setEnabled(true);
                enabled_fuzz_body_xml.setEnabled(true);
                enabled_fuzz_body_multipart.setEnabled(true);
                enabled_fuzz_bad_json.setEnabled(true);
            } else {
                enabled_fuzz_body_form.setSelected(false);
                enabled_fuzz_body_json.setSelected(false);
                enabled_fuzz_body_xml.setSelected(false);
                enabled_fuzz_body_multipart.setSelected(false);
                enabled_fuzz_bad_json.setSelected(false);
                enabled_fuzz_body_form.setEnabled(false);
                enabled_fuzz_body_json.setEnabled(false);
                enabled_fuzz_body_xml.setEnabled(false);
                enabled_fuzz_body_multipart.setEnabled(false);
                enabled_fuzz_bad_json.setEnabled(false);
            }
        });
        subPanel4.add(enabled_fuzz_body);

        JPanel subPanel5 = UIUtil.GetXJPanel();
        enabled_fuzz_body_form = new JCheckBox("Enable Body-Form Fuzz");
        subPanel5.add(enabled_fuzz_body_form);

        JPanel subPanel6 = UIUtil.GetXJPanel();
        enabled_fuzz_body_json = new JCheckBox("Enable Body-Json Fuzz");
        subPanel6.add(enabled_fuzz_body_json);

        JPanel subPanel7 = UIUtil.GetXJPanel();
        enabled_fuzz_body_xml = new JCheckBox("Enable Body-Xml Fuzz");
        subPanel7.add(enabled_fuzz_body_xml);

        JPanel subPanel8 = UIUtil.GetXJPanel();
        enabled_fuzz_body_multipart = new JCheckBox("Enable Body-Multipart Fuzz");
        subPanel8.add(enabled_fuzz_body_multipart);

        JPanel subPanel9 = UIUtil.GetXJPanel();
        enabled_fuzz_bad_json = new JCheckBox("Enable Bad-Json Fuzz");
        subPanel9.add(enabled_fuzz_bad_json);

        JButton applyBtn = new JButton("Apply");
        applyBtn.setMaximumSize(applyBtn.getPreferredSize());
        applyBtn.addActionListener(e -> {
            this.saveConfig();
        });

        panel1.add(subPanel0);
        panel1.add(subPanel1);
        panel1.add(subPanel2);
        panel1.add(subPanel3);
        panel1.add(subPanel4);
        panel1.add(subPanel5);
        panel1.add(subPanel6);
        panel1.add(subPanel7);
        panel1.add(subPanel8);
        panel1.add(subPanel9);
        panel1.add(applyBtn);
        return panel1;
    }

    private void loadConfig() {
        fuzzModeSelector.setSelectedItem(Config.get(Config.FUZZ_MODE, Config.FuzzMode.EachFuzz.name()));
        enabled_fuzz_header.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_HEADER, true));
        enabled_fuzz_url.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_URL, true));
        enabled_fuzz_body.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_BODY, true));
        enabled_fuzz_cookie.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_COOKIE, true));
        enabled_fuzz_body_form.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_BODY_FORM, true));
        enabled_fuzz_body_json.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_BODY_JSON, true));
        enabled_fuzz_body_multipart.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_BODY_MULTIPART, true));
        enabled_fuzz_body_xml.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_BODY_XML, true));
        enabled_fuzz_bad_json.setSelected(Config.getBoolean(Config.ENABLED_FUZZ_BAD_JSON, false));
    }

    private void saveConfig() {
        Config.set(Config.FUZZ_MODE, fuzzModeSelector.getSelectedItem().toString());
        Config.setBoolean(Config.ENABLED_FUZZ_HEADER, enabled_fuzz_header.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_URL, enabled_fuzz_url.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_BODY, enabled_fuzz_body.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_COOKIE, enabled_fuzz_cookie.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_BODY_FORM, enabled_fuzz_body_form.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_BODY_JSON, enabled_fuzz_body_json.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_BODY_MULTIPART, enabled_fuzz_body_multipart.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_BODY_XML, enabled_fuzz_body_xml.isSelected());
        Config.setBoolean(Config.ENABLED_FUZZ_BAD_JSON, enabled_fuzz_bad_json.isSelected());
        JOptionPane.showMessageDialog(mainPanel, "Apply success!");
    }

    private String[] GetFuzzModes() {
        ArrayList<String> algStrs = new ArrayList<String>();
        Config.FuzzMode[] backends = Config.FuzzMode.values();
        for (Config.FuzzMode backend : backends) {
            algStrs.add(backend.name().replace('_', '/'));
        }
        return algStrs.toArray(new String[algStrs.size()]);
    }
}
