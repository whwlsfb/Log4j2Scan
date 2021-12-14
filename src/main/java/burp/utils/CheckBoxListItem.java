package burp.utils;

import burp.poc.IPOC;

import javax.swing.*;
import java.awt.*;
import java.util.Map;

public class CheckBoxListItem extends JCheckBox implements ListCellRenderer {
    public CheckBoxListItem() {
        super();
    }

    public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected,
                                                  boolean cellHasFocus) {
        Map.Entry<Integer, IPOC> val = (Map.Entry<Integer, IPOC>) value;
        this.setText(String.format("%s - %s -  %s", val.getKey(), getTypeName(val.getValue().getType()), val.getValue().generate("example.com")));
        setBackground(isSelected ? list.getSelectionBackground() : list.getBackground());
        setForeground(isSelected ? list.getSelectionForeground() : list.getForeground());
        this.setSelected(isSelected);
        return this;
    }

    private String getTypeName(int type) {
        switch (type) {
            case IPOC.POC_TYPE_LDAP:
                return "LDAP";
            case IPOC.POC_TYPE_DNS:
                return "DNS";
            case IPOC.POC_TYPE_RMI:
                return "RMI";
            default:
                return "unknown";
        }
    }
}