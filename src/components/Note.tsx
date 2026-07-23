import React from 'react';
import {View, Text, StyleSheet, Button, Alert} from 'react-native';
/*
 * SECURITY FIX (Code Injection): replaced the dangerous eval()
 * call with safeEvaluate(), a whitelist-based arithmetic parser
 * that can never execute arbitrary code. See REPORT.md II-A.
 */
import {safeEvaluate} from '../utils/safeEvaluate';

interface IProps {
  title: string;
  text: string;
}

function Note(props: IProps) {
  function evaluateEquation() {
    /* SECURITY FIX (Code Injection): evaluate via the safe parser
     * and handle invalid input gracefully instead of running it. */
    try {
      const result = safeEvaluate(props.text);
      Alert.alert('Result', 'Result: ' + result);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Invalid equation.';
      Alert.alert('Invalid equation', message);
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>{props.title}</Text>
      <Text style={styles.text}>{props.text}</Text>

      <View style={styles.evaluateContainer}>
        <Button title="Evaluate" onPress={evaluateEquation} />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    padding: 10,
    marginTop: 5,
    marginBottom: 5,
    backgroundColor: '#fff',
    borderRadius: 5,
    borderColor: 'black',
    borderWidth: 1,
  },
  title: {
    fontSize: 18,
    fontWeight: 'bold',
  },
  text: {
    fontSize: 16,
  },
  evaluateContainer: {
    marginTop: 10,
    marginBottom: 10,
  },
});

export default Note;
