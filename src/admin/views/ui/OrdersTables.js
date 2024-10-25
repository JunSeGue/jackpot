import OrderTable from "../../components/tables/OrderTable";
import {Row, Col} from "reactstrap";

const OrdersTables = () => {
    return (
        <Row>
            <Col lg="12">
                <OrderTable/>
            </Col>
        </Row>
    );
};

export default OrdersTables;
