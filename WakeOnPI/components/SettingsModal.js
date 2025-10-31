import React from "react";
import { Modal, View, Text, StyleSheet, TouchableOpacity } from "react-native";

const SettingsModal = ({ visible, onClose }) => {
  return (
    <Modal visible={visible} animationType="slide" transparent>
      <View style={styles.overlay}>
        <View style={styles.modal}>
          <Text style={styles.title}>Einstellungen</Text>
          <Text style={styles.option}>• Dummy Option 1</Text>
          <Text style={styles.option}>• Dummy Option 2</Text>
          <Text style={styles.option}>• Dummy Option 3</Text>

          <TouchableOpacity style={styles.closeButton} onPress={onClose}>
            <Text style={styles.closeButtonText}>Schließen</Text>
          </TouchableOpacity>
        </View>
      </View>
    </Modal>
  );
};

export default SettingsModal;

const styles = StyleSheet.create({
  overlay: {
    flex: 1,
    backgroundColor: "rgba(0,0,0,0.6)",
    justifyContent: "center",
    alignItems: "center",
  },
  modal: {
    width: "80%",
    backgroundColor: "#1E1E1E",
    borderRadius: 10,
    padding: 20,
  },
  title: {
    color: "#fff",
    fontSize: 22,
    marginBottom: 10,
  },
  option: {
    color: "#ccc",
    fontSize: 16,
    marginVertical: 4,
  },
  closeButton: {
    marginTop: 20,
    backgroundColor: "#4CAF50",
    borderRadius: 6,
    paddingVertical: 8,
    alignItems: "center",
  },
  closeButtonText: {
    color: "#fff",
    fontWeight: "bold",
  },
});
