/*
 * Licensed to DuraSpace under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 *
 * DuraSpace licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.fcrepo.kernel.impl.services;

import static org.slf4j.LoggerFactory.getLogger;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.sql.DataSource;
import javax.transaction.Transactional;
import org.apache.jena.graph.Node;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.graph.Triple;
import org.fcrepo.common.db.DbPlatform;
import org.fcrepo.kernel.api.identifiers.FedoraId;
import org.slf4j.Logger;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.init.DatabasePopulatorUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.stereotype.Component;

import com.google.common.base.Preconditions;

/**
 * Manager for the membership index
 *
 * @author bbpennel
 */
@Component
public class MembershipIndexManager {
    private static final Logger log = getLogger(MembershipIndexManager.class);

    private static final Timestamp NO_END_TIMESTAMP = Timestamp.from(MembershipServiceImpl.NO_END_INSTANT);
    private static final Timestamp NO_START_TIMESTAMP = Timestamp.from(Instant.parse("1000-01-01T00:00:00.000Z"));

    private static final String ADD_OPERATION = "add";
    private static final String DELETE_OPERATION = "delete";
    private static final String FORCE_FLAG = "force";

    private static final String TX_ID_PARAM = "txId";
    private static final String SUBJECT_ID_PARAM = "subjectId";
    private static final String NO_END_TIME_PARAM = "noEndTime";
    private static final String ADD_OP_PARAM = "addOp";
    private static final String DELETE_OP_PARAM = "deleteOp";
    private static final String MEMENTO_TIME_PARAM = "mementoTime";
    private static final String PROPERTY_PARAM = "property";
    private static final String TARGET_ID_PARAM = "targetId";
    private static final String SOURCE_ID_PARAM = "sourceId";
    private static final String START_TIME_PARAM = "startTime";
    private static final String END_TIME_PARAM = "endTime";
    private static final String OPERATION_PARAM = "operation";
    private static final String FORCE_PARAM = "forceFlag";
    private static final String OBJECT_ID_PARAM = "objectId";

    private static final String SELECT_ALL_MEMBERSHIP = "SELECT * FROM membership";

    private static final String SELECT_ALL_OPERATIONS = "SELECT * FROM membership_tx_operations";

    private static final String SELECT_MEMBERSHIP_IN_TX =
            "SELECT m.property, m.object_id" +
            " FROM membership m" +
            " WHERE subject_id = :subjectId" +
                " AND end_time = :noEndTime" +
                " AND NOT EXISTS (" +
                    " SELECT 1" +
                    " FROM membership_tx_operations mto" +
                    " WHERE mto.subject_id = :subjectId" +
                        " AND mto.source_id = m.source_id" +
                        " AND mto.object_id = m.object_id" +
                        " AND mto.tx_id = :txId" +
                        " AND mto.operation = :deleteOp)" +
            " UNION" +
            " SELECT property, object_id" +
            " FROM membership_tx_operations" +
            " WHERE subject_id = :subjectId" +
                " AND tx_id = :txId" +
                " AND end_time = :noEndTime" +
                " AND operation = :addOp";

    private static final String SELECT_MEMBERSHIP_MEMENTO_IN_TX =
            "SELECT property, object_id" +
            " FROM membership m" +
            " WHERE m.subject_id = :subjectId" +
                " AND m.start_time <= :mementoTime" +
                " AND m.end_time > :mementoTime" +
                " AND NOT EXISTS (" +
                    " SELECT 1" +
                    " FROM membership_tx_operations mto" +
                    " WHERE mto.subject_id = :subjectId" +
                        " AND mto.source_id = m.source_id" +
                        " AND mto.property = m.property" +
                        " AND mto.object_id = m.object_id" +
                        " AND mto.end_time <= :mementoTime" +
                        " AND mto.tx_id = :txId" +
                        " AND mto.operation = :deleteOp)" +
            " UNION" +
            " SELECT property, object_id" +
            " FROM membership_tx_operations" +
            " WHERE subject_id = :subjectId" +
                " AND tx_id = :txId" +
                " AND start_time <= :mementoTime" +
                " AND end_time > :mementoTime" +
                " AND operation = :addOp";

    private static final String INSERT_MEMBERSHIP_IN_TX =
            "INSERT INTO membership_tx_operations" +
            " (subject_id, property, object_id, source_id, start_time, end_time, tx_id, operation)" +
            " VALUES (:subjectId, :property, :targetId, :sourceId, :startTime, :endTime, :txId, :operation)";

    private static final String END_EXISTING_MEMBERSHIP =
            "INSERT INTO membership_tx_operations" +
            " (subject_id, property, object_id, source_id, start_time, end_time, tx_id, operation)" +
            " SELECT m.subject_id, m.property, m.object_id, m.source_id, m.start_time, :endTime, :txId, :deleteOp" +
            " FROM membership m" +
            " WHERE m.source_id = :sourceId" +
                " AND m.end_time = :noEndTime" +
                " AND m.subject_id = :subjectId" +
                " AND m.property = :property" +
                " AND m.object_id = :objectId";

    private static final String CLEAR_ENTRY_IN_TX =
            "DELETE FROM membership_tx_operations" +
            " WHERE source_id = :sourceId" +
                " AND tx_id = :txId" +
                " AND subject_id = :subjectId" +
                " AND property = :property" +
                " AND object_id = :objectId" +
                " AND operation = :operation" +
                " AND force_flag IS NULL";

    private static final String CLEAR_ALL_ADDED_FOR_SOURCE_IN_TX =
            "DELETE FROM membership_tx_operations" +
            " WHERE source_id = :sourceId" +
                " AND tx_id = :txId" +
                " AND operation = :addOp";

    // Add "delete" entries for all existing membership from the given source, if not already deleted
    private static final String END_EXISTING_FOR_SOURCE =
            "INSERT INTO membership_tx_operations" +
            " (subject_id, property, object_id, source_id, start_time, end_time, tx_id, operation)" +
            " SELECT subject_id, property, object_id, source_id, start_time, :endTime, :txId, :deleteOp" +
            " FROM membership m" +
            " WHERE source_id = :sourceId" +
                " AND end_time = :noEndTime" +
                " AND NOT EXISTS (" +
                    " SELECT TRUE" +
                    " FROM membership_tx_operations mtx" +
                    " WHERE mtx.subject_id = m.subject_id" +
                        " AND mtx.property = m.property" +
                        " AND mtx.object_id = m.object_id" +
                        " AND mtx.source_id = m.source_id" +
                        " AND mtx.operation = :deleteOp" +
                    ")";

    private static final String DELETE_EXISTING_FOR_SOURCE_AFTER =
            "INSERT INTO membership_tx_operations" +
            " (subject_id, property, object_id, source_id, start_time, end_time, tx_id, operation, force_flag)" +
            " SELECT subject_id, property, object_id, source_id, start_time, end_time, :txId, :deleteOp, :forceFlag" +
            " FROM membership m" +
            " WHERE m.source_id = :sourceId" +
                " AND (m.start_time >= :startTime" +
                " OR m.end_time >= :startTime)";

    private static final String PURGE_ALL_REFERENCES_MEMBERSHIP =
            "DELETE from membership" +
            " where source_id = :targetId" +
                " OR subject_id = :targetId" +
                " OR object_id = :targetId";

    private static final String PURGE_ALL_REFERENCES_TRANSACTION =
            "DELETE from membership_tx_operations" +
            " WHERE tx_id = :txId" +
                " AND (source_id = :targetId" +
                " OR subject_id = :targetId" +
                " OR object_id = :targetId)";

    private static final String COMMIT_DELETES =
            "DELETE from membership" +
            " WHERE EXISTS (" +
                " SELECT TRUE" +
                " FROM membership_tx_operations mto" +
                " WHERE mto.tx_id = :txId" +
                    " AND mto.operation = :deleteOp" +
                    " AND mto.force_flag = :forceFlag" +
                    " AND membership.source_id = mto.source_id" +
                    " AND membership.subject_id = mto.subject_id" +
                    " AND membership.property = mto.property" +
                    " AND membership.object_id = mto.object_id" +
                " )";

    private static final String COMMIT_ENDS_H2 =
            "UPDATE membership m" +
            " SET end_time = (" +
                " SELECT mto.end_time" +
                " FROM membership_tx_operations mto" +
                " WHERE mto.tx_id = :txId" +
                    " AND m.source_id = mto.source_id" +
                    " AND m.subject_id = mto.subject_id" +
                    " AND m.property = mto.property" +
                    " AND m.object_id = mto.object_id" +
                    " AND mto.operation = :deleteOp" +
                " )" +
            " WHERE EXISTS (" +
                "SELECT TRUE" +
                " FROM membership_tx_operations mto" +
                " WHERE mto.tx_id = :txId" +
                    " AND mto.operation = :deleteOp" +
                    " AND m.source_id = mto.source_id" +
                    " AND m.subject_id = mto.subject_id" +
                    " AND m.property = mto.property" +
                    " AND m.object_id = mto.object_id" +
                " )";

    private static final String COMMIT_ENDS_POSTGRES =
            "UPDATE membership" +
            " SET end_time = mto.end_time" +
            " FROM membership_tx_operations mto" +
            " WHERE mto.tx_id = :txId" +
                " AND mto.operation = :deleteOp" +
                " AND membership.source_id = mto.source_id" +
                " AND membership.subject_id = mto.subject_id" +
                " AND membership.property = mto.property" +
                " AND membership.object_id = mto.object_id";

    private static final String COMMIT_ENDS_MYSQL =
            "UPDATE membership m" +
            " INNER JOIN membership_tx_operations mto ON" +
                " m.source_id = mto.source_id" +
                " AND m.subject_id = mto.subject_id" +
                " AND m.subject_id = mto.subject_id" +
                " AND m.property = mto.property" +
                " AND m.object_id = mto.object_id" +
            " SET m.end_time = mto.end_time" +
            " WHERE mto.tx_id = :txId" +
                " AND mto.operation = :deleteOp";

    private static final Map<DbPlatform, String> COMMIT_ENDS_MAP = Map.of(
            DbPlatform.MYSQL, COMMIT_ENDS_MYSQL,
            DbPlatform.MARIADB, COMMIT_ENDS_MYSQL,
            DbPlatform.POSTGRESQL, COMMIT_ENDS_POSTGRES,
            DbPlatform.H2, COMMIT_ENDS_H2
    );

    // Transfer all "add" operations from tx to committed membership, unless the entry already exists
    private static final String COMMIT_ADDS =
            "INSERT INTO membership" +
            " (subject_id, property, object_id, source_id, start_time, end_time)" +
            " SELECT subject_id, property, object_id, source_id, start_time, end_time" +
            " FROM membership_tx_operations mto" +
            " WHERE mto.tx_id = :txId" +
                " AND mto.operation = :addOp" +
                " AND NOT EXISTS (" +
                    " SELECT TRUE" +
                    " FROM membership m" +
                    " WHERE m.source_id = mto.source_id" +
                        " AND m.subject_id = mto.subject_id" +
                        " AND m.property = mto.property" +
                        " AND m.object_id = mto.object_id" +
                        " AND m.start_time = mto.start_time" +
                        " AND m.end_time = mto.end_time" +
                " )";

    private static final String DELETE_TRANSACTION =
            "DELETE FROM membership_tx_operations" +
            " WHERE tx_id = :txId";

    private static final String TRUNCATE_MEMBERSHIP = "TRUNCATE TABLE membership";

    private static final String TRUNCATE_MEMBERSHIP_TX = "TRUNCATE TABLE membership_tx_operations";

    @Inject
    private DataSource dataSource;

    private NamedParameterJdbcTemplate jdbcTemplate;

    private DbPlatform dbPlatform;

    private static final Map<DbPlatform, String> DDL_MAP = Map.of(
            DbPlatform.MYSQL, "sql/mysql-membership.sql",
            DbPlatform.H2, "sql/default-membership.sql",
            DbPlatform.POSTGRESQL, "sql/default-membership.sql",
            DbPlatform.MARIADB, "sql/mariadb-membership.sql"
    );

    @PostConstruct
    public void setUp() {
        jdbcTemplate = new NamedParameterJdbcTemplate(getDataSource());

        dbPlatform = DbPlatform.fromDataSource(dataSource);

        Preconditions.checkArgument(DDL_MAP.containsKey(dbPlatform),
                "Missing DDL mapping for %s", dbPlatform);

        final var ddl = DDL_MAP.get(dbPlatform);
        log.debug("Applying ddl: {}", ddl);
        DatabasePopulatorUtils.execute(
                new ResourceDatabasePopulator(new DefaultResourceLoader().getResource("classpath:" + ddl)),
                dataSource);
    }

    /**
     * End a membership entry, setting an end time if committed, or clearing from the current tx
     * if it was newly added.
     *
     * @param txId transaction id
     * @param sourceId ID of the direct/indirect container whose membership should be ended
     * @param membership membership triple to end
     * @param endTime the time the resource was deleted, generally its last modified
     */
    @Transactional
    public void endMembership(final String txId,  final FedoraId sourceId, final Triple membership,
            final Instant endTime) {
        final Map<String, Object> parameterSource = Map.of(
                TX_ID_PARAM, txId,
                SOURCE_ID_PARAM, sourceId.getFullId(),
                SUBJECT_ID_PARAM, membership.getSubject().getURI(),
                PROPERTY_PARAM, membership.getPredicate().getURI(),
                OBJECT_ID_PARAM, membership.getObject().getURI(),
                OPERATION_PARAM, ADD_OPERATION);

        final int affected = jdbcTemplate.update(CLEAR_ENTRY_IN_TX, parameterSource);

        // If no rows were deleted, then assume we need to delete permanent entry
        if (affected == 0) {
            final Map<String, Object> parameterSource2 = Map.of(
                    TX_ID_PARAM, txId,
                    SOURCE_ID_PARAM, sourceId.getFullId(),
                    SUBJECT_ID_PARAM, membership.getSubject().getURI(),
                    PROPERTY_PARAM, membership.getPredicate().getURI(),
                    OBJECT_ID_PARAM, membership.getObject().getURI(),
                    END_TIME_PARAM, formatInstant(endTime),
                    NO_END_TIME_PARAM, NO_END_TIMESTAMP,
                    DELETE_OP_PARAM, DELETE_OPERATION);
            jdbcTemplate.update(END_EXISTING_MEMBERSHIP, parameterSource2);
        }
    }

    /**
     * End all membership properties resulting from the specified source container
     * @param txId transaction id
     * @param sourceId ID of the direct/indirect container whose membership should be ended
     * @param endTime the time the resource was deleted, generally its last modified
     */
    @Transactional
    public void endMembershipForSource(final String txId, final FedoraId sourceId, final Instant endTime) {
        final Map<String, Object> parameterSource = Map.of(
                TX_ID_PARAM, txId,
                SOURCE_ID_PARAM, sourceId.getFullId(),
                ADD_OP_PARAM, ADD_OPERATION);

        jdbcTemplate.update(CLEAR_ALL_ADDED_FOR_SOURCE_IN_TX, parameterSource);

        final Map<String, Object> parameterSource2 = Map.of(
                TX_ID_PARAM, txId,
                SOURCE_ID_PARAM, sourceId.getFullId(),
                END_TIME_PARAM, formatInstant(endTime),
                NO_END_TIME_PARAM, NO_END_TIMESTAMP,
                DELETE_OP_PARAM, DELETE_OPERATION);
        jdbcTemplate.update(END_EXISTING_FOR_SOURCE, parameterSource2);
    }

    /**
     * Delete membership entries that are active at or after the given timestamp for the specified source
     * @param txId transaction id
     * @param sourceId ID of the direct/indirect container
     * @param afterTime time at or after which membership should be removed
     */
    @Transactional
    public void deleteMembershipForSourceAfter(final String txId, final FedoraId sourceId, final Instant afterTime) {
        // Clear all membership added in this transaction
        final Map<String, Object> parameterSource = Map.of(
                TX_ID_PARAM, txId,
                SOURCE_ID_PARAM, sourceId.getFullId(),
                ADD_OP_PARAM, ADD_OPERATION);

        jdbcTemplate.update(CLEAR_ALL_ADDED_FOR_SOURCE_IN_TX, parameterSource);

        final var afterTimestamp = afterTime == null ? NO_START_TIMESTAMP : formatInstant(afterTime);

        // Delete all existing membership entries that start after or end after the given timestamp
        final Map<String, Object> parameterSource2 = Map.of(
                TX_ID_PARAM, txId,
                SOURCE_ID_PARAM, sourceId.getFullId(),
                START_TIME_PARAM, afterTimestamp,
                FORCE_PARAM, FORCE_FLAG,
                DELETE_OP_PARAM, DELETE_OPERATION);
        jdbcTemplate.update(DELETE_EXISTING_FOR_SOURCE_AFTER, parameterSource2);
    }

    /**
     * Clean up any references to the target id, in transactions and outside
     * @param txId transaction id
     * @param targetId identifier of the resource to cleanup membership references for
     */
    @Transactional
    public void deleteMembershipReferences(final String txId, final FedoraId targetId) {
        final Map<String, Object> parameterSource = Map.of(
                TARGET_ID_PARAM, targetId.getFullId(),
                TX_ID_PARAM, txId);

        jdbcTemplate.update(PURGE_ALL_REFERENCES_TRANSACTION, parameterSource);
        jdbcTemplate.update(PURGE_ALL_REFERENCES_MEMBERSHIP, parameterSource);
    }

    /**
     * Add new membership property to the index, clearing any delete
     * operations for the property if necessary.
     * @param txId transaction id
     * @param sourceId ID of the direct/indirect container which produced the membership
     * @param membership membership triple
     * @param startTime time the membership triple was added
     */
    @Transactional
    public void addMembership(final String txId, final FedoraId sourceId, final Triple membership,
            final Instant startTime) {
        // Clear any existing delete operation for this membership
        final Map<String, Object> parametersDelete = Map.of(
                TX_ID_PARAM, txId,
                SOURCE_ID_PARAM, sourceId.getFullId(),
                SUBJECT_ID_PARAM, membership.getSubject().getURI(),
                PROPERTY_PARAM, membership.getPredicate().getURI(),
                OBJECT_ID_PARAM, membership.getObject().getURI(),
                OPERATION_PARAM, DELETE_OPERATION);

        jdbcTemplate.update(CLEAR_ENTRY_IN_TX, parametersDelete);

        // Add the new membership operation
        addMembership(txId, sourceId, membership, startTime, null);
    }

    /**
     * Add new membership property to the index
     * @param txId transaction id
     * @param sourceId ID of the direct/indirect container which produced the membership
     * @param membership membership triple
     * @param startTime time the membership triple was added
     * @param endTime time the membership triple ends, or never if not provided
     */
    public void addMembership(final String txId, final FedoraId sourceId, final Triple membership,
            final Instant startTime, final Instant endTime) {
        final var endTimestamp = endTime == null ? NO_END_TIMESTAMP : formatInstant(endTime);
        // Add the new membership operation
        final Map<String, Object> parameterSource = Map.of(
                SUBJECT_ID_PARAM, membership.getSubject().getURI(),
                PROPERTY_PARAM, membership.getPredicate().getURI(),
                TARGET_ID_PARAM, membership.getObject().getURI(),
                SOURCE_ID_PARAM, sourceId.getFullId(),
                START_TIME_PARAM, formatInstant(startTime),
                END_TIME_PARAM, endTimestamp,
                TX_ID_PARAM, txId,
                OPERATION_PARAM, ADD_OPERATION);

        jdbcTemplate.update(INSERT_MEMBERSHIP_IN_TX, parameterSource);
    }

    /**
     * Get a stream of membership triples with
     * @param txId transaction from which membership will be retrieved, or null for no transaction
     * @param subjectId ID of the subject
     * @return Stream of membership triples
     */
    public Stream<Triple> getMembership(final String txId, final FedoraId subjectId) {
        final Node subjectNode = NodeFactory.createURI(subjectId.getBaseId());

        final RowMapper<Triple> membershipMapper = (rs, rowNum) ->
                Triple.create(subjectNode,
                              NodeFactory.createURI(rs.getString("property")),
                              NodeFactory.createURI(rs.getString("object_id")));

        List<Triple> membership = null;
        if (subjectId.isMemento()) {
            final Map<String, Object> parameterSource = Map.of(
                    SUBJECT_ID_PARAM, subjectId.getBaseId(),
                    MEMENTO_TIME_PARAM, formatInstant(subjectId.getMementoInstant()),
                    TX_ID_PARAM, txId,
                    ADD_OP_PARAM, ADD_OPERATION,
                    DELETE_OP_PARAM, DELETE_OPERATION);

            membership = jdbcTemplate.query(SELECT_MEMBERSHIP_MEMENTO_IN_TX, parameterSource, membershipMapper);
        } else {
            final Map<String, Object> parameterSource = Map.of(
                    SUBJECT_ID_PARAM, subjectId.getFullId(),
                    NO_END_TIME_PARAM, NO_END_TIMESTAMP,
                    TX_ID_PARAM, txId,
                    ADD_OP_PARAM, ADD_OPERATION,
                    DELETE_OP_PARAM, DELETE_OPERATION);

            membership = jdbcTemplate.query(SELECT_MEMBERSHIP_IN_TX, parameterSource, membershipMapper);
        }

        return membership.stream();
    }

    /**
     * Perform a commit of operations stored in the specified transaction
     * @param txId transaction id
     */
    @Transactional
    public void commitTransaction(final String txId) {
        final Map<String, String> parameterSource = Map.of(TX_ID_PARAM, txId,
                ADD_OP_PARAM, ADD_OPERATION,
                DELETE_OP_PARAM, DELETE_OPERATION,
                FORCE_PARAM, FORCE_FLAG);

        jdbcTemplate.update(COMMIT_DELETES, parameterSource);
        final int ends = jdbcTemplate.update(COMMIT_ENDS_MAP.get(this.dbPlatform), parameterSource);
        final int adds = jdbcTemplate.update(COMMIT_ADDS, parameterSource);
        final int cleaned = jdbcTemplate.update(DELETE_TRANSACTION, parameterSource);

        log.debug("Completed commit, {} ended, {} adds, {} operations", ends, adds, cleaned);
    }

    /**
     * Delete all entries related to a transaction
     * @param txId transaction id
     */
    public void deleteTransaction(final String txId) {
        final Map<String, String> parameterSource = Map.of(TX_ID_PARAM, txId);
        jdbcTemplate.update(DELETE_TRANSACTION, parameterSource);
    }

    /**
     * Format an instant to a timestamp without milliseconds, due to precision
     * issues with memento datetimes.
     * @param instant
     * @return
     */
    private Timestamp formatInstant(final Instant instant) {
        final var timestamp = Timestamp.from(instant);
        timestamp.setNanos(0);
        return timestamp;
    }

    /**
     * Clear all entries from the index
     */
    @Transactional
    public void clearIndex() {
        jdbcTemplate.update(TRUNCATE_MEMBERSHIP, Map.of());
        jdbcTemplate.update(TRUNCATE_MEMBERSHIP_TX, Map.of());
    }

    /**
     * Log all membership entries, for debugging usage only
     */
    public void logMembership() {
        log.info("source_id, subject_id, property, object_id, start_time, end_time");
        jdbcTemplate.query(SELECT_ALL_MEMBERSHIP, new RowCallbackHandler() {
            @Override
            public void processRow(final ResultSet rs) throws SQLException {
                log.info("{}, {}, {}, {}, {}, {}", rs.getString("source_id"), rs.getString("subject_id"),
                        rs.getString("property"), rs.getString("object_id"), rs.getTimestamp("start_time"),
                        rs.getTimestamp("end_time"));
            }
        });
    }

    /**
     * Log all membership operations, for debugging usage only
     */
    public void logOperations() {
        log.info("source_id, subject_id, property, object_id, start_time, end_time, tx_id, operation, force_flag");
        jdbcTemplate.query(SELECT_ALL_OPERATIONS, new RowCallbackHandler() {
            @Override
            public void processRow(final ResultSet rs) throws SQLException {
                log.info("{}, {}, {}, {}, {}, {}, {}, {}, {}",
                        rs.getString("source_id"), rs.getString("subject_id"), rs.getString("property"),
                        rs.getString("object_id"), rs.getTimestamp("start_time"), rs.getTimestamp("end_time"),
                        rs.getString("tx_id"), rs.getString("operation"), rs.getString("force_flag"));
            }
        });
    }

    /**
     * Set the JDBC datastore.
     * @param dataSource the dataStore.
     */
    public void setDataSource(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    /**
     * Get the JDBC datastore.
     * @return the dataStore.
     */
    public DataSource getDataSource() {
        return dataSource;
    }
}
