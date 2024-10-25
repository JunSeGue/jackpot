import BoardTables from "../../components/tables/BoardTable";
import {Row, Col} from "reactstrap";

const BoardsTables = () => {
    return (
        <Row>
            <Col lg="12">
                <BoardTables/>
            </Col>
        </Row>
    );
};

export default BoardsTables;
