import DogTables from "../../components/tables/DogTable";
import {Row, Col} from "reactstrap";
import "../../assets/scss/style.scss";

const DogsTables = () => {
    return (
        <Row>

            <Col lg="12">
                <DogTables/>
            </Col>
        </Row>
    );
};

export default DogsTables;
