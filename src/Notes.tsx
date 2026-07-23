import React from 'react';
import {
  View,
  Text,
  TextInput,
  Button,
  StyleSheet,
  Alert,
  SafeAreaView,
  ScrollView,
} from 'react-native';
import Note from './components/Note';
import {NativeStackScreenProps} from '@react-navigation/native-stack';
import {TRootStackParamList} from './App';
/*
 * SECURITY FIX (Insecure Data Storage): note persistence now goes
 * through src/utils/secureStorage.ts, which AES-encrypts the data
 * and keys it by username only (never the password). This screen
 * no longer touches AsyncStorage directly. See REPORT.md II-C.
 */
import {saveNotes, loadNotes, INote} from './utils/secureStorage';

export type {INote};

interface IProps {}

interface IState {
  notes: INote[];
  newNoteTitle: string;
  newNoteEquation: string;
}

type TProps = NativeStackScreenProps<TRootStackParamList, 'Notes'> & IProps;

export default class Notes extends React.Component<TProps, IState> {
  constructor(props: Readonly<TProps>) {
    super(props);

    this.state = {
      notes: [],
      newNoteTitle: '',
      newNoteEquation: '',
    };

    this.onNoteTitleChange = this.onNoteTitleChange.bind(this);
    this.onNoteEquationChange = this.onNoteEquationChange.bind(this);
    this.addNote = this.addNote.bind(this);
  }

  public async componentDidMount() {
    const existing = await this.getStoredNotes();

    this.setState({notes: existing});
  }

  public async componentWillUnmount() {
    this.storeNotes(this.state.notes);
  }

  /* SECURITY FIX (Insecure Data Storage): load/persist notes via the
   * encrypted store, keyed by username only. The password is no
   * longer read here (it is not even present on the user object). */
  private async getStoredNotes(): Promise<INote[]> {
    return loadNotes(this.props.route.params.user.username);
  }

  private async storeNotes(notes: INote[]) {
    try {
      await saveNotes(this.props.route.params.user.username, notes);
    } catch {
      Alert.alert('Error', 'Could not save your notes securely.');
    }
  }

  private onNoteTitleChange(value: string) {
    this.setState({newNoteTitle: value});
  }

  private onNoteEquationChange(value: string) {
    this.setState({newNoteEquation: value});
  }

  private addNote() {
    /* ============================================================
     * SECURITY FIX (Insufficient Input Validation): validate and
     * bound both fields before accepting a note. The equation is
     * checked against the same arithmetic whitelist used at
     * evaluation time, so obviously-invalid / injected input is
     * rejected up front rather than stored. See REPORT.md II-D.
     * ============================================================ */
    const title = this.state.newNoteTitle.trim();
    const text = this.state.newNoteEquation.trim();

    if (title === '' || text === '') {
      Alert.alert('Error', 'Title and equation cannot be empty.');
      return;
    }

    if (title.length > 100) {
      Alert.alert('Error', 'Title is too long (max 100 characters).');
      return;
    }

    // Whitelist: only arithmetic characters are allowed in an equation.
    if (!/^[0-9+\-*/().\s]+$/.test(text)) {
      Alert.alert(
        'Error',
        'Equation may only contain numbers and + - * / ( ) characters.',
      );
      return;
    }

    const note: INote = {title, text};

    this.setState({
      notes: this.state.notes.concat(note),
      newNoteTitle: '',
      newNoteEquation: '',
    });
  }

  public render() {
    return (
      <SafeAreaView>
        <ScrollView contentInsetAdjustmentBehavior="automatic">
          <View style={styles.container}>
            <Text style={styles.title}>
              {'Math Notes: ' + this.props.route.params.user.username}
            </Text>
            <TextInput
              style={styles.titleInput}
              value={this.state.newNoteTitle}
              onChangeText={this.onNoteTitleChange}
              placeholder="Enter your title"
            />
            <TextInput
              style={styles.textInput}
              value={this.state.newNoteEquation}
              onChangeText={this.onNoteEquationChange}
              placeholder="Enter your math equation"
            />
            <Button title="Add Note" onPress={this.addNote} />

            <View style={styles.notes}>
              {this.state.notes.map((note, index) => (
                <Note key={index} title={note.title} text={note.text} />
              ))}
            </View>
          </View>
        </ScrollView>
      </SafeAreaView>
    );
  }
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
  titleInput: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    marginBottom: 10,
  },
  textInput: {
    borderWidth: 1,
    borderColor: '#ccc',
    padding: 10,
    marginBottom: 10,
  },
  notes: {
    marginTop: 15,
  },
});
