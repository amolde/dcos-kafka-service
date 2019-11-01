package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strconv"
	"strings"
)

const (
	kerberosEnvvar        = "SECURITY_KERBEROS_ENABLED"
	tlsEncryptionEnvvar   = "SECURITY_TRANSPORT_ENCRYPTION_ENABLED"
	tlsAllowPlainEnvvar   = "SECURITY_TRANSPORT_ENCRYPTION_ALLOW_PLAINTEXT"
	brokerPort            = "KAFKA_BROKER_PORT"
	brokerPortTLS         = "KAFKA_BROKER_PORT_TLS"
	taskNameEnvvar        = "TASK_NAME"
	frameworkNameEnvvar   = "FRAMEWORK_NAME"
	frameworkHostEnvvar   = "FRAMEWORK_HOST"
	ipEnvvar              = "MESOS_CONTAINER_IP"
	kerberosPrimaryEnvvar = "SECURITY_KERBEROS_PRIMARY"
	kerberosRealmEnvvar   = "SECURITY_KERBEROS_REALM"
	sslAuthEnvvar         = "SECURITY_SSL_AUTHENTICATION_ENABLED"
	authorizationEnvvar   = "SECURITY_AUTHORIZATION_ENABLED"
	superUsersEnvvar      = "SECURITY_AUTHORIZATION_SUPER_USERS"
	brokerCountEnvvar     = "BROKER_COUNT"
	advertiseHostIPEnvvar = "KAFKA_ADVERTISE_HOST"
	externalAdvertisedListenerEnvvar = "EXTERNAL_ADVERTISED_LISTENER"

	listenersProperty           = "listeners"
	advertisedListenersProperty = "advertised.listeners"
	listenerProtocolMapProperty = "listener.security.protocol.map"
	interBrokerProtocolProperty = "inter.broker.listener.name"
	superUsersProperty          = "super.users"

	externalProtocol            = "EXTERNAL"
	secondExternalProtocol      = "EXTERNAL2"

	// Based on the RFC5280 the CN cannot be longer than 64 characters
	// ub-common-name INTEGER ::= 64
	cnMaxLength = 64
)

func main() {
	log.Printf("Starting setup-helper...")
	log.Printf("Calculating security and listener settings...")
	err := calculateSettings()
	if err != nil {
		log.Fatalf("Failed to calculate security and listener settings: %s", err.Error())
	}
	log.Printf("Calculated security and listener settings")
	log.Printf("setup-helper complete")
}

func getBooleanEnvvar(envvar string) bool {
	val, set := os.LookupEnv(envvar)
	if !set {
		return false
	}

	result, err := strconv.ParseBool(val)
	if err != nil {
		log.Printf("Could not parse boolean for envvar: %s (%s)",
			envvar,
			err.Error(),
		)
		return false
	}

	return result
}

func getIntEnvvar(envvar string) int {
	val, set := os.LookupEnv(envvar)
	if !set {
		return 0
	}

	result, err := strconv.Atoi(val)
	if err != nil {
		log.Printf("Could not parse int for envvar: %s (%s)",
			envvar,
			err.Error(),
		)
		return 0
	}

	return result
}

func getStringEnvvar(envvar string) string {
	return os.Getenv(envvar)
}

func calculateSettings() error {
	log.Printf("Setting listeners...")
	err := setListeners()
	if err != nil {
		return err
	}
	log.Printf("Set listeners")

	log.Print("Setting inter.broker.listener.name...")
	err = setInterBrokerProtocol()
	if err != nil {
		return err
	}
	log.Print("Set inter.broker.listener.name")

	log.Print("Setting super.users")
	err = setSuperUsers()
	if err != nil {
		return err
	}
	log.Print("Set super.users")
	return nil
}

func parseToggles() (kerberos bool, tls bool, plaintext bool, authz bool, sslAuth bool) {
	return getBooleanEnvvar(kerberosEnvvar),
		getBooleanEnvvar(tlsEncryptionEnvvar),
		getBooleanEnvvar(tlsAllowPlainEnvvar),
		getBooleanEnvvar(authorizationEnvvar),
		getBooleanEnvvar(sslAuthEnvvar)
}

func setListeners() error {
	var listeners []string
	var advertisedListeners []string
	listenerProtocolMap := make(map[string]string)

	kerberosEnabled, tlsEncryptionEnabled, allowPlainText, _, _ := parseToggles()

	if kerberosEnabled { // Kerberos enabled

		if tlsEncryptionEnabled { // Transport encryption on
			listeners = append(listeners,
				getListener("SASL_SSL", brokerPortTLS, true))
			listeners = append(listeners,
				getListener(externalProtocol, getExternalListenerPort(0), false))
			advertisedListeners = append(advertisedListeners,
				getExternalListener(externalProtocol, 0, "SASL_SSL", brokerPortTLS, false))
			advertisedListeners = append(advertisedListeners,
				getListener("SASL_SSL", brokerPortTLS, true))
			listenerProtocolMap["SASL_SSL"] = "SASL_SSL"
			listenerProtocolMap[externalProtocol] = listenerProtocolMap["SASL_SSL"]

			if allowPlainText { // Allow plaintext as well
				listeners = append(listeners,
					getListener("SASL_PLAINTEXT", brokerPort, true))
				listeners = append(listeners,
					getListener(secondExternalProtocol, getExternalListenerPort(1), false))
				advertisedListeners = append(advertisedListeners,
					getExternalListener(secondExternalProtocol, 1, "SASL_PLAINTEXT", brokerPort, false))
				advertisedListeners = append(advertisedListeners,
					getListener("SASL_PLAINTEXT", brokerPort, true))
				listenerProtocolMap["SASL_PLAINTEXT"] = "SASL_PLAINTEXT"
				listenerProtocolMap[secondExternalProtocol] = listenerProtocolMap["SASL_PLAINTEXT"]
			}
		} else { // Plaintext only
			listeners = append(listeners,
				getListener("SASL_PLAINTEXT", brokerPort, true))
			listeners = append(listeners,
				getListener(externalProtocol, getExternalListenerPort(0), false))
			advertisedListeners = append(advertisedListeners,
				getExternalListener(externalProtocol, 0, "SASL_PLAINTEXT", brokerPort, false))
			advertisedListeners = append(advertisedListeners,
				getListener("SASL_PLAINTEXT", brokerPort, true))
			listenerProtocolMap["SASL_PLAINTEXT"] = "SASL_PLAINTEXT"
			listenerProtocolMap[externalProtocol] = listenerProtocolMap["SASL_PLAINTEXT"]
		}

	} else if tlsEncryptionEnabled { // No kerberos, but Transport encryption is on
		listeners = append(listeners,
			getListener("SSL", brokerPortTLS, true))
		listeners = append(listeners,
			getListener(externalProtocol, getExternalListenerPort(0), false))
		advertisedListeners = append(advertisedListeners,
			getExternalListener(externalProtocol, 0, "SSL", brokerPortTLS, false))
		advertisedListeners = append(advertisedListeners,
			getListener("SSL", brokerPortTLS, true))
		listenerProtocolMap["SSL"] = "SSL"
		listenerProtocolMap[externalProtocol] = listenerProtocolMap["SSL"]

		if allowPlainText { // Plaintext allowed
			listeners = append(listeners,
				getListener("PLAINTEXT", brokerPort, true))
			listeners = append(listeners,
				getListener(secondExternalProtocol, getExternalListenerPort(1), false))
			advertisedListeners = append(advertisedListeners,
				getExternalListener(secondExternalProtocol, 1, "PLAINTEXT", brokerPort, false))
			advertisedListeners = append(advertisedListeners,
				getListener("PLAINTEXT", brokerPort, true))
			listenerProtocolMap["PLAINTEXT"] = "PLAINTEXT"
			listenerProtocolMap[secondExternalProtocol] = listenerProtocolMap["PLAINTEXT"]
		}
	} else { // No TLS, no Kerberos, Plaintext only
		listeners = append(listeners,
			getListener("PLAINTEXT", brokerPort, true))
		listeners = append(listeners,
			getListener(externalProtocol, getExternalListenerPort(0), false))
		// NOTE: To be consistent with the legacy behavior of the 2.0.X Kafka series,
		// we advertise the IP address rather than the host name.
		advertisedListeners = append(advertisedListeners,
			getExternalListener(externalProtocol, 0, "PLAINTEXT", brokerPort, true))
		advertisedListeners = append(advertisedListeners,
			getListener("PLAINTEXT", brokerPort, true))
		listenerProtocolMap["PLAINTEXT"] = "PLAINTEXT"
		listenerProtocolMap[externalProtocol] = listenerProtocolMap["PLAINTEXT"]		
	}
	
	err := writeToWorkingDirectory(listenersProperty,
		"listeners="+strings.Join(listeners, ","))

	var listenerProtocolMapList []string
	for key,value := range listenerProtocolMap{
		listenerProtocolMapList = append(listenerProtocolMapList, fmt.Sprintf("%s:%s", key, value))
	}
	
	err = writeToWorkingDirectory(listenerProtocolMapProperty,
		"listener.security.protocol.map="+strings.Join(listenerProtocolMapList, ","))

	// NOTE: To be consistent with the legacy behavior of the 2.0.X Kafka series,
	// when there is no security enabled, we must honor the kafka.kafka_advertise_host_ip
	// configuration parameter
	if kerberosEnabled || tlsEncryptionEnabled || getBooleanEnvvar(advertiseHostIPEnvvar) {
		err = writeToWorkingDirectory(advertisedListenersProperty,
			"advertised.listeners="+strings.Join(advertisedListeners, ","))
	} else {
		err = writeToWorkingDirectory(advertisedListenersProperty, "")
	}

	return err
}

func getListener(protocol string, portEnvvar string, isEnvVar bool) string {
	port := portEnvvar
	if (isEnvVar) {
		port = getStringEnvvar(portEnvvar)
	}
	return fmt.Sprintf("%s://%s:%s",
		protocol,
		getStringEnvvar(ipEnvvar),
		port,
	)
}

func getExternalListenerPort(offset int) string {
	return strconv.Itoa(29092 + offset)
}

func getAdvertisedExternalListenerPort(offset int) string {
	return strconv.Itoa(9092 + offset)
}

func getExternalListener(externalProtocol string, externalPortOffset int, protocol string, portEnvvar string, useIp bool) string {
	if (getStringEnvvar(externalAdvertisedListenerEnvvar) != "") {	
		portNumberIncrement := 0
		if(getStringEnvvar("POD_INSTANCE_INDEX") != "") {
			portNumberIncrement = getIntEnvvar("POD_INSTANCE_INDEX")
		}
		return fmt.Sprintf("%s://%s:%s",
			externalProtocol,
			getStringEnvvar(externalAdvertisedListenerEnvvar),
			getAdvertisedExternalListenerPort(externalPortOffset + portNumberIncrement))
	}
	if (useIp) {
		return getListener(protocol, portEnvvar, true)
	}
	return getAdvertisedListener(protocol, portEnvvar)
}

func getAdvertisedListener(protocol string, portEnvvar string) string {
	return fmt.Sprintf("%s://%s.%s:%s",
		protocol,
		getStringEnvvar(taskNameEnvvar),
		getStringEnvvar(frameworkHostEnvvar),
		getStringEnvvar(portEnvvar),
	)
}

func writeToWorkingDirectory(filename string, content string) error {
	log.Printf("Attempting to write to %s:\n%s", filename, content)
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	log.Printf("Calculated working directory as: %s", wd)

	return ioutil.WriteFile(
		path.Join(wd, filename),
		[]byte(content),
		0644,
	)
}

func setInterBrokerProtocol() error {
	kerberosEnabled, tlsEncryptionEnabled, _, _, _ := parseToggles()

	protocol := ""
	if kerberosEnabled {
		if tlsEncryptionEnabled {
			protocol = "SASL_SSL"
		} else {
			protocol = "SASL_PLAINTEXT"
		}
	} else if tlsEncryptionEnabled {
		protocol = "SSL"
	} else {
		protocol = "PLAINTEXT"
	}

	return writeToWorkingDirectory(interBrokerProtocolProperty,
		fmt.Sprintf("%s=%s", interBrokerProtocolProperty, protocol))
}

func setSuperUsers() error {
	kerberosEnabled, _, _, authzEnabled, sslAuthEnabled := parseToggles()

	var superUsers []string
	superUsersString := getStringEnvvar(superUsersEnvvar)
	if superUsersString != "" {
		superUsers = strings.Split(superUsersString, ";")
	}

	if authzEnabled {
		if kerberosEnabled {
			superUsers = append(superUsers, fmt.Sprintf("User:%s", getStringEnvvar(kerberosPrimaryEnvvar)))
		} else if sslAuthEnabled {
			superUsers = append(superUsers, getBrokerSSLSuperUsers()...)
		}
	}

	return writeToWorkingDirectory(superUsersProperty, strings.Join(superUsers, ";"))
}

func getBrokerSSLSuperUsers() []string {
	var supers []string
	for i := 0; i < getIntEnvvar(brokerCountEnvvar); i++ {
		cn := fmt.Sprintf("kafka-%d-broker.%s",
			i,
			strings.Replace(getStringEnvvar(frameworkNameEnvvar), "/", "", -1))

		if length := len(cn); length > cnMaxLength {
			cn = cn[length-cnMaxLength:]
		}
		supers = append(supers, fmt.Sprintf(`User:%s`, cn))
	}

	return supers
}
