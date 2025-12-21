import TextEditor from "./TextEditor";
import {
  BrowserRouter as Router,
  Route,
  Redirect,
  Switch,
} from "react-router-dom";
import { v4 as uuidV4 } from "uuid";

function App() {
  return (
    <Router>
      <Switch>
        <Route
          exact
          path="/"
          render={() => <Redirect to={`/documents/${uuidV4()}`} />}
        />
        <Route path="/documents/:id" component={TextEditor} />
      </Switch>
    </Router>
  );
}

export default App;
