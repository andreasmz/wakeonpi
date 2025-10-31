import React, { useState } from "react";
import { View, FlatList, StyleSheet, Text, TouchableOpacity, Alert } from "react-native";
import Icon from "react-native-vector-icons/Ionicons";
import DeviceItem from "../components/DeviceItem";
import SettingsModal from "../components/SettingsModal";
import { useEffect } from "react";
import { StatusBar, Platform } from "react-native";
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import AsyncStorage from '@react-native-async-storage/async-storage';

import {devices} from "../api/Logic";

const App = () => {
  const [settingsVisible, setSettingsVisible] = useState(false);

  // const STORAGE_KEY = '@wakeonpi_devices';
  // const [devices, setDevices] = React.useState(defaultDevices);

  // Load saved devices on mount
  // useEffect(() => {
  //   const loadDevices = async () => {
  //     try {
  //       const raw = await AsyncStorage.getItem(STORAGE_KEY);
  //       if (raw) {
  //         const parsed = JSON.parse(raw);
  //         if (Array.isArray(parsed)) {
  //           setDevices(parsed);
  //           return;
  //         }
  //       }
  //       // No saved data, save defaults
  //       await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(defaultDevices));
  //     } catch (e) {
  //       console.warn('Failed to load devices from storage', e);
  //     }
  //   };

  //   loadDevices();
  // }, []);

  // // Save devices whenever they change
  // useEffect(() => {
  //   const save = async () => {
  //     try {
  //       await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(devices));
  //     } catch (e) {
  //       console.warn('Failed to save devices', e);
  //     }
  //   };
  //   save();
  // }, [devices]);


  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.container} edges={["top", "left", "right"]}>
        <StatusBar
          hidden={false}
          translucent={false}
          backgroundColor="#1E1E1E"
          barStyle="light-content"
        />

        {/* Header */}
        <View style={styles.header}>
          <View style={styles.logoPlaceholder}>
            <Text style={styles.logoText}>LOGO</Text>
          </View>

          <Text style={styles.headerTitle}>WakeOnPI</Text>

          <View style={styles.headerRight}>
            <TouchableOpacity
              style={styles.addButton}
              onPress={() => Alert.alert('Add pressed')}
              accessibilityLabel="Add device"
            >
              <Icon name="add" size={20} color="#fff" />
            </TouchableOpacity>

            <TouchableOpacity onPress={() => setSettingsVisible(true)} style={styles.settingsButton}>
              <Icon name="settings-outline" size={24} color="#fff" />
            </TouchableOpacity>
          </View>
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
  headerRight: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  addButton: {
    width: 36,
    height: 36,
    borderRadius: 18,
    backgroundColor: '#000',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 10,
  },
  listContainer: {
    padding: 10,
  },
});
