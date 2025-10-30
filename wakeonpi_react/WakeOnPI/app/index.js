import React, { useState } from "react";
import { View, FlatList, StyleSheet, Text, TouchableOpacity } from "react-native";
import Icon from "react-native-vector-icons/Ionicons";
import DeviceItem from "../components/DeviceItem";
import SettingsModal from "../components/SettingsModal";
import { useEffect } from "react";
import { StatusBar, Platform } from "react-native";
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import AsyncStorage from '@react-native-async-storage/async-storage';

const App = () => {
  const [settingsVisible, setSettingsVisible] = useState(false);

  const defaultDevices = [
    { id: "1", name: "Gaming PC", status: "Offline", mac: "AA:BB:CC:DD:EE:FF" },
    { id: "2", name: "NAS Server", status: "Online", mac: "11:22:33:44:55:66" },
    { id: "3", name: "Media Center", status: "Offline", mac: "77:88:99:AA:BB:CC" },
  ];

  const STORAGE_KEY = '@wakeonpi_devices';
  const [devices, setDevices] = React.useState(defaultDevices);

  // Load saved devices on mount
  useEffect(() => {
    const loadDevices = async () => {
      try {
        const raw = await AsyncStorage.getItem(STORAGE_KEY);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) {
            setDevices(parsed);
            return;
          }
        }
        // No saved data, save defaults
        await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(defaultDevices));
      } catch (e) {
        console.warn('Failed to load devices from storage', e);
      }
    };

    loadDevices();
  }, []);

  // Save devices whenever they change
  useEffect(() => {
    const save = async () => {
      try {
        await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(devices));
      } catch (e) {
        console.warn('Failed to save devices', e);
      }
    };
    save();
  }, [devices]);


  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.container} edges={["top", "left", "right"]}>
        <StatusBar
          hidden={false}
          translucent={false} // ensure StatusBar does not overlay content on Android/Expo Go
          backgroundColor="#1E1E1E"
          barStyle="light-content"
        />
        {/* Header */}
        <View style={styles.header}>
          <View style={styles.logoPlaceholder}>
            <Text style={styles.logoText}>LOGO</Text>
          </View>
          <Text style={styles.headerTitle}>Wake On LAN</Text>
          <TouchableOpacity onPress={() => setSettingsVisible(true)} style={styles.settingsButton}>
            <Icon name="settings-outline" size={28} color="#fff" />
          </TouchableOpacity>
        </View>

        {/* Device List */}
        <FlatList
          data={devices}
          keyExtractor={(item) => item.id}
          renderItem={({ item }) => (
            <DeviceItem
              device={item}
              onUpdateDevice={(updated) =>
                setDevices((prev) => prev.map((d) => (d.id === updated.id ? updated : d)))
              }
            />
          )}
          contentContainerStyle={styles.listContainer}
        />

        {/* Settings Modal */}
        <SettingsModal visible={settingsVisible} onClose={() => setSettingsVisible(false)} />
      </SafeAreaView>
    </SafeAreaProvider>
  );
};

export default App;

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#121212",
  },
  header: {
    height: 60,
    backgroundColor: "#1E1E1E",
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    paddingHorizontal: 15,
  },
  logoPlaceholder: {
    width: 50,
    height: 40,
    justifyContent: "center",
    alignItems: "center",
    borderWidth: 1,
    borderColor: "#666",
    borderRadius: 6,
  },
  logoText: {
    color: "#888",
    fontSize: 12,
  },
  headerTitle: {
    color: "#fff",
    fontSize: 20,
    fontWeight: "bold",
  },
  settingsButton: {
    padding: 5,
  },
  listContainer: {
    padding: 10,
  },
});
