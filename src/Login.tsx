import React from 'react';
import {View, Text, TextInput, Button, StyleSheet, Alert} from 'react-native';
import type {NativeStackScreenProps} from '@react-navigation/native-stack';
import {TRootStackParamList} from './App';
/* ============================================================
 * SECURITY FIX (Improper Authentication): authentication logic and
 * the credential store now live in src/utils/auth.ts. This screen
 * no longer contains any hardcoded plaintext passwords. See
 * REPORT.md II-B.
 * ============================================================ */
import {verifyCredentials, IAuthUser} from './utils/auth';

/* IUser now carries ONLY the username. The password is never stored
 * on, or passed through, the authenticated user object. */
export type IUser = IAuthUser;

interface IProps {
  onLogin: (user: IUser) => void;
}

type TProps = NativeStackScreenProps<TRootStackParamList, 'Login'> & IProps;

export default function Login(props: TProps) {
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');

  function login() {
    /*
     * SECURITY FIX (Improper Authentication + Insufficient Input
     * Validation): delegate to verifyCredentials(), which compares
     * a PBKDF2 hash of the entered password against a salted hash
     * (no plaintext comparison, no hardcoded passwords here).
     */
    const authenticatedUser = verifyCredentials(username, password);

    if (authenticatedUser) {
      // Clear the password from component state after use.
      setPassword('');
      props.onLogin(authenticatedUser);
    } else {
      // Generic message — do not reveal whether t  he username exists.
      Alert.alert('Error', 'Username or password is invalid.');
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Login</Text>
      <TextInput
        style={styles.username}
        value={username}
        onChangeText={setUsername}
        placeholder="Username"
        autoCapitalize="none"
        autoCorrect={false}
      />
      <TextInput
        style={styles.password}
        value={password}
        onChangeText={setPassword}
        placeholder="Password"
        /* SECURITY FIX: mask password input so it is not shown
         * on-screen or captured by screenshots. */
        secureTextEntry={true}
        autoCapitalize="none"
        autoCorrect={false}
      />
      <Button title="Login" onPress={login} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: '#fff',
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    marginBottom: 20,
  },
  username: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    marginBottom: 10,
  },
  password: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    marginBottom: 10,
  },
});
