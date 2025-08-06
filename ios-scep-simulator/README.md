# iOS SCEP Client Simulator

A web application that simulates Apple devices (iPhone, iPad, Mac, Apple Watch) requesting certificates via the Simple Certificate Enrollment Protocol (SCEP).

## Features

- **Device Simulation**: Realistic Apple device profiles with proper model identifiers, serial numbers, and OS versions
- **SCEP Protocol Support**: Complete SCEP workflow including GetCACert, GetCACaps, and PKIOperation
- **Certificate Generation**: Automatic RSA key pair generation and Certificate Signing Request (CSR) creation
- **Web Interface**: Clean, responsive web interface for easy device simulation
- **Multiple Device Types**: Support for iPhone, iPad, Mac, and Apple Watch
- **Real-time Testing**: Built-in SCEP server connectivity testing
- **Export Results**: Download enrollment results as JSON files

## Supported Devices

| Device | Model | OS Version | Icon |
|--------|-------|------------|------|
| iPhone 15 Pro | iPhone16,1 | 17.5.1 | 📱 |
| iPad Pro 12.9" | iPad14,6 | 17.5.1 | 📟 |
| MacBook Pro | Mac14,9 | 14.5 | 💻 |
| Apple Watch Series 9 | Watch6,10 | 10.5 | ⌚ |

## Quick Start

### Using Docker Compose (Recommended)

1. Start the simulator:
```bash
docker-compose up -d
```

2. Open your browser to `http://localhost:3000`

3. Configure your SCEP server URL and start testing

### Manual Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Access the web interface at `http://localhost:3000`

## SCEP Workflow

The simulator performs the complete SCEP enrollment process:

1. **Key Generation**: Creates an RSA 2048-bit key pair for the device
2. **CSR Creation**: Generates a Certificate Signing Request with device-specific information
3. **GetCACert**: Retrieves the CA certificate from the SCEP server
4. **GetCACaps**: Gets the CA capabilities and supported operations
5. **PKIOperation**: Submits the CSR for certificate enrollment

## API Endpoints

- `GET /` - Main device selection page
- `GET /device/<device_type>` - Device-specific enrollment page
- `POST /api/scep/test` - Test SCEP server connectivity
- `POST /api/scep/enroll` - Perform certificate enrollment
- `GET /api/devices` - List available device profiles
- `GET /health` - Health check endpoint

## Configuration

### Environment Variables

- `SCEP_SERVER_URL`: Base URL of the SCEP server (default: `https://localhost`)
- `FLASK_ENV`: Flask environment (default: `production`)

### SCEP Server Configuration

The simulator expects the SCEP endpoint to be available at:
```
{SCEP_SERVER_URL}/scep/pkiclient
```

For the CA Manager, this would typically be:
```
https://localhost/scep/pkiclient
```

## Usage with CA Manager

This simulator is designed to work with the CA Manager PKI system:

1. Start CA Manager and complete the setup wizard
2. Ensure PKI is initialized and CA is built
3. Start the iOS SCEP Simulator
4. Use `https://localhost/scep/pkiclient` as the SCEP server URL
5. Select a device type and perform enrollment

## Development

### Project Structure

```
ios-scep-simulator/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Dockerfile            # Docker container configuration
├── docker-compose.yml    # Docker Compose setup
├── templates/            # HTML templates
│   ├── base.html        # Base template with styling
│   ├── index.html       # Device selection page
│   └── device.html      # Device enrollment page
└── README.md            # This file
```

### Adding New Device Types

To add a new device type:

1. Add the device profile to `DEVICE_PROFILES` in `app.py`:
```python
'new_device': {
    'name': 'Device Name',
    'model': 'ModelIdentifier',
    'os_version': '1.0.0',
    'serial': 'SERIALNUMBER',
    'udid': str(uuid.uuid4()),
    'icon': '📱'
}
```

2. The device will automatically appear in the web interface

### Security Notes

- The simulator disables SSL certificate verification for testing with self-signed certificates
- Private keys are generated in memory and not persisted
- Challenge passwords are handled securely
- All device UUIDs are randomly generated for each session

## Troubleshooting

### Connection Issues

- Verify the SCEP server URL is correct and accessible
- Check that the CA Manager SCEP endpoint is enabled
- Ensure firewall rules allow access to the SCEP port

### Certificate Enrollment Failures

- Verify the CA is properly initialized in CA Manager
- Check if a challenge password is required
- Review the SCEP server logs for detailed error information

### Docker Issues

- Ensure port 3000 is not in use by another application
- Check Docker logs: `docker-compose logs ios-scep-simulator`
- Rebuild the container: `docker-compose build ios-scep-simulator`

## License

This simulator is part of the CA Manager PKI system and follows the same licensing terms.