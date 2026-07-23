/**
 * Sample React Native App
 * https://github.com/facebook/react-native
 *
 * @format
 */

import React from 'react';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';

import Notes from './Notes';
import Login, { IUser } from './Login';

/* ============================================================
 * SECURITY FIX (Insecure Data Storage / Improper Authentication):
 * IUser now contains only the username (see src/utils/auth.ts), so
 * a password is never carried through navigation params or app
 * state. See REPORT.md II-B and II-C.
 * ============================================================ */
export type TRootStackParamList = {
    Login: undefined;
    Notes: {
        user: IUser;
    };
};

function App() {
    const [signedInAs, setSignedInAs] = React.useState<IUser | false>(false);

    const Stack = createNativeStackNavigator<TRootStackParamList>();

    return (
        <NavigationContainer>
            <Stack.Navigator>
                {
                    !signedInAs ?
                        <Stack.Screen name="Login">
                            {(props) => <Login {...props} onLogin={(user) => setSignedInAs(user)} />}
                        </Stack.Screen> :
                        <Stack.Screen name="Notes" component={Notes} initialParams={{ user: signedInAs }} />
                }
            </Stack.Navigator>
        </NavigationContainer>
    );
}

export default App;
