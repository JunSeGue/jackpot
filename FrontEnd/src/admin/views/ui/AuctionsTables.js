import AuctionTable from "../../components/tables/AuctionTable";
import {Row, Col} from "reactstrap";

const AuctionsTables = () => {
    return (
        <Row>
            <Col lg="12">
                <AuctionTable/>
            </Col>
        </Row>
    );
};

export default AuctionsTables;
