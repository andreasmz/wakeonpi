

interface Device {
    uuid: string,
    name: string,
    mac: string,
    ip: string
}

export const devices: Device[] = [];

function add_device(name: string, mac: string, ip: string): boolean {
    devices.push({
        uuid: "",
        name: name,
        mac: mac,
        ip: ip,
    });
    return true;
}