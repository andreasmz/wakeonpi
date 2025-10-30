import React, { useState } from "react";
import { View, Text, StyleSheet, TouchableOpacity, Alert } from "react-native";
import Icon from "react-native-vector-icons/MaterialCommunityIcons";

const DeviceItem = ({ device, onUpdateDevice }) => {
  const [loading, setLoading] = useState(false);

  const handleStart = async () => {
    // Update UI optimistically
    try {
      setLoading(true);
      onUpdateDevice && onUpdateDevice({ ...device, status: 'Starting' });

      // Send HTTPS request to example.com (GET). Replace with configured URL as needed.
      const response = await fetch('https://example.com');
      const text = await response.text();

      // Update status based on response.ok
      const newStatus = response.ok ? 'Online' : 'Offline';
      onUpdateDevice && onUpdateDevice({ ...device, status: newStatus });

      // Show a readout with HTTP code and a short snippet of the body
      const snippet = text ? text.slice(0, 300) : '<no body>';
      Alert.alert(
        `Request result (${response.status})`,
        `${snippet}${text && text.length > 300 ? '\n\n...truncated' : ''}`,
        [{ text: 'OK' }]
      );
    } catch (e) {
      onUpdateDevice && onUpdateDevice({ ...device, status: 'Error' });
      Alert.alert('Request failed', e.message || String(e));
    } finally {
      setLoading(false);
    }
  };

  return (
    <View style={styles.container}>
      <Icon
        name={device.status === "Online" ? "desktop-classic" : "monitor-off"}
        size={60}
        color={device.status === "Online" ? "#4CAF50" : "#888"}
        style={styles.icon}
      />
      <View style={styles.infoContainer}>
        <Text style={styles.name}>{device.name}</Text>
        <Text style={styles.status}>{device.status}</Text>
        <TouchableOpacity style={styles.startButton} onPress={handleStart} disabled={loading}>
          <Text style={styles.startButtonText}>{loading ? '...' : 'Start'}</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};

export default DeviceItem;

const styles = StyleSheet.create({
  container: {
    flexDirection: "row",
    backgroundColor: "#1E1E1E",
    padding: 15,
    borderRadius: 10,
    marginVertical: 8,
    alignItems: "center",
    minHeight: "30%", // etwa 30% der Bildschirmhöhe
  },
  icon: {
    marginRight: 20,
  },
  infoContainer: {
    flex: 1,
    justifyContent: "space-between",
  },
  name: {
    color: "#fff",
    fontSize: 20,
    fontWeight: "bold",
  },
  status: {
    color: "#888",
    fontSize: 14,
    marginVertical: 4,
  },
  startButton: {
    backgroundColor: "#4CAF50",
    paddingVertical: 8,
    borderRadius: 6,
    alignSelf: "flex-start",
    paddingHorizontal: 20,
  },
  startButtonText: {
    color: "#fff",
    fontWeight: "bold",
  },
});
